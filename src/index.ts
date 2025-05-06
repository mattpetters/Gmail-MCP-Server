import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import {
    isInitializeRequest,
} from "@modelcontextprotocol/sdk/types.js";
import { google } from 'googleapis';
import { z } from "zod";
import { OAuth2Client } from 'google-auth-library';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import http from 'http';
import open from 'open';
import os from 'os';
import { createEmailMessage } from "./utl.js";
import { createLabel, updateLabel, deleteLabel, listLabels, getOrCreateLabel, GmailLabel } from "./label-manager.js";
import express from "express";
import { Request, Response } from "express";
import { randomUUID } from "crypto";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { pino } from 'pino';
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const logger = pino({ level: process.env.LOG_LEVEL || 'info' });

// Configuration paths
const CONFIG_DIR = path.join(os.homedir(), '.gmail-mcp');
const OAUTH_PATH = process.env.GMAIL_OAUTH_PATH || path.join(CONFIG_DIR, 'gcp-oauth.keys.json');
const CREDENTIALS_PATH = process.env.GMAIL_CREDENTIALS_PATH || path.join(CONFIG_DIR, 'credentials.json');

// Type definitions for Gmail API responses
interface GmailMessagePart {
    partId?: string;
    mimeType?: string;
    filename?: string;
    headers?: Array<{
        name: string;
        value: string;
    }>;
    body?: {
        attachmentId?: string;
        size?: number;
        data?: string;
    };
    parts?: GmailMessagePart[];
}

interface EmailAttachment {
    id: string;
    filename: string;
    mimeType: string;
    size: number;
}

interface EmailContent {
    text: string;
    html: string;
}

// OAuth2 configuration
let oauth2Client: OAuth2Client;

/**
 * Recursively extract email body content from MIME message parts
 * Handles complex email structures with nested parts
 */
function extractEmailContent(messagePart: GmailMessagePart): EmailContent {
    // Initialize containers for different content types
    let textContent = '';
    let htmlContent = '';

    // If the part has a body with data, process it based on MIME type
    if (messagePart.body && messagePart.body.data) {
        const content = Buffer.from(messagePart.body.data, 'base64').toString('utf8');

        // Store content based on its MIME type
        if (messagePart.mimeType === 'text/plain') {
            textContent = content;
        } else if (messagePart.mimeType === 'text/html') {
            htmlContent = content;
        }
    }

    // If the part has nested parts, recursively process them
    if (messagePart.parts && messagePart.parts.length > 0) {
        for (const part of messagePart.parts) {
            const { text, html } = extractEmailContent(part);
            if (text) textContent += text;
            if (html) htmlContent += html;
        }
    }

    // Return both plain text and HTML content
    return { text: textContent, html: htmlContent };
}

async function loadCredentials() {
    try {
        // Create config directory if it doesn't exist
        if (!process.env.GMAIL_OAUTH_PATH && !CREDENTIALS_PATH && !fs.existsSync(CONFIG_DIR)) {
            fs.mkdirSync(CONFIG_DIR, { recursive: true });
        }

        // Check for OAuth keys in current directory first, then in config directory
        const localOAuthPath = path.join(process.cwd(), 'gcp-oauth.keys.json');
        let oauthPath = OAUTH_PATH;

        if (fs.existsSync(localOAuthPath)) {
            // If found in current directory, copy to config directory
            fs.copyFileSync(localOAuthPath, OAUTH_PATH);
            logger.info('OAuth keys found in current directory, copied to global config.');
        }

        if (!fs.existsSync(OAUTH_PATH)) {
            logger.error('Error: OAuth keys file not found. Please place gcp-oauth.keys.json in current directory or', CONFIG_DIR);
            process.exit(1);
        }

        const keysContent = JSON.parse(fs.readFileSync(OAUTH_PATH, 'utf8'));
        const keys = keysContent.installed || keysContent.web;

        if (!keys) {
            logger.error('Error: Invalid OAuth keys file format. File should contain either "installed" or "web" credentials.');
            process.exit(1);
        }

        const callback = process.argv[2] === 'auth' && process.argv[3]
            ? process.argv[3]
            : "http://localhost:3000/oauth2callback";

        oauth2Client = new OAuth2Client(
            keys.client_id,
            keys.client_secret,
            callback
        );

        if (fs.existsSync(CREDENTIALS_PATH)) {
            const credentials = JSON.parse(fs.readFileSync(CREDENTIALS_PATH, 'utf8'));
            oauth2Client.setCredentials(credentials);
        }
    } catch (error) {
        logger.error('Error loading credentials:', error);
        process.exit(1);
    }
}

async function authenticate() {
    const server = http.createServer();
    server.listen(3000);

    return new Promise<void>((resolve, reject) => {
        const authUrl = oauth2Client.generateAuthUrl({
            access_type: 'offline',
            scope: ['https://www.googleapis.com/auth/gmail.modify'],
        });

        logger.info('Please visit this URL to authenticate:', authUrl);
        open(authUrl);

        server.on('request', async (req, res) => {
            if (!req.url?.startsWith('/oauth2callback')) return;

            const url = new URL(req.url, 'http://localhost:3000');
            const code = url.searchParams.get('code');

            if (!code) {
                res.writeHead(400);
                res.end('No code provided');
                reject(new Error('No code provided'));
                return;
            }

            try {
                const { tokens } = await oauth2Client.getToken(code);
                oauth2Client.setCredentials(tokens);
                fs.writeFileSync(CREDENTIALS_PATH, JSON.stringify(tokens));

                res.writeHead(200);
                res.end('Authentication successful! You can close this window.');
                server.close();
                resolve();
            } catch (error) {
                res.writeHead(500);
                res.end('Authentication failed');
                logger.error('Authentication failed:', error);
                reject(error);
            }
        });
    });
}

// Schema definitions
const SendEmailSchema = z.object({
    to: z.array(z.string()).describe("List of recipient email addresses"),
    subject: z.string().describe("Email subject"),
    body: z.string().describe("Email body content"),
    cc: z.array(z.string()).optional().describe("List of CC recipients"),
    bcc: z.array(z.string()).optional().describe("List of BCC recipients"),
    threadId: z.string().optional().describe("Thread ID to reply to"),
    inReplyTo: z.string().optional().describe("Message ID being replied to"),
});

const ReadEmailSchema = z.object({
    messageId: z.string().describe("ID of the email message to retrieve"),
});

const SearchEmailsSchema = z.object({
    query: z.string().describe("Gmail search query (e.g., 'from:example@gmail.com')"),
    maxResults: z.number().optional().describe("Maximum number of results to return"),
});

// Updated schema to include removeLabelIds
const ModifyEmailSchema = z.object({
    messageId: z.string().describe("ID of the email message to modify"),
    labelIds: z.array(z.string()).optional().describe("List of label IDs to apply"),
    addLabelIds: z.array(z.string()).optional().describe("List of label IDs to add to the message"),
    removeLabelIds: z.array(z.string()).optional().describe("List of label IDs to remove from the message"),
});

const DeleteEmailSchema = z.object({
    messageId: z.string().describe("ID of the email message to delete"),
});

// New schema for listing email labels
const ListEmailLabelsSchema = z.object({}).describe("Retrieves all available Gmail labels");

// Label management schemas
const CreateLabelSchema = z.object({
    name: z.string().describe("Name for the new label"),
    messageListVisibility: z.enum(['show', 'hide']).optional().describe("Whether to show or hide the label in the message list"),
    labelListVisibility: z.enum(['labelShow', 'labelShowIfUnread', 'labelHide']).optional().describe("Visibility of the label in the label list"),
}).describe("Creates a new Gmail label");

const UpdateLabelSchema = z.object({
    id: z.string().describe("ID of the label to update"),
    name: z.string().optional().describe("New name for the label"),
    messageListVisibility: z.enum(['show', 'hide']).optional().describe("Whether to show or hide the label in the message list"),
    labelListVisibility: z.enum(['labelShow', 'labelShowIfUnread', 'labelHide']).optional().describe("Visibility of the label in the label list"),
}).describe("Updates an existing Gmail label");

const DeleteLabelSchema = z.object({
    id: z.string().describe("ID of the label to delete"),
}).describe("Deletes a Gmail label");

const GetOrCreateLabelSchema = z.object({
    name: z.string().describe("Name of the label to get or create"),
    messageListVisibility: z.enum(['show', 'hide']).optional().describe("Whether to show or hide the label in the message list"),
    labelListVisibility: z.enum(['labelShow', 'labelShowIfUnread', 'labelHide']).optional().describe("Visibility of the label in the label list"),
}).describe("Gets an existing label by name or creates it if it doesn't exist");

// Schemas for batch operations
const BatchModifyEmailsSchema = z.object({
    messageIds: z.array(z.string()).describe("List of message IDs to modify"),
    addLabelIds: z.array(z.string()).optional().describe("List of label IDs to add to all messages"),
    removeLabelIds: z.array(z.string()).optional().describe("List of label IDs to remove from all messages"),
    batchSize: z.number().optional().default(50).describe("Number of messages to process in each batch (default: 50)"),
});

const BatchDeleteEmailsSchema = z.object({
    messageIds: z.array(z.string()).describe("List of message IDs to delete"),
    batchSize: z.number().optional().default(50).describe("Number of messages to process in each batch (default: 50)"),
});

// Main function
async function main() {
    await loadCredentials();

    if (process.argv[2] === 'auth') {
        await authenticate();
        logger.info('Authentication completed successfully');
        process.exit(0);
    }

    // Initialize Gmail API
    const gmail = google.gmail({ version: 'v1', auth: oauth2Client });

    // --- Initialize McpServer helper class ---
    const server = new McpServer({
        name: "gmail",
        version: "1.0.0",
    });

    // --- Helper function for email sending/drafting ---
    async function handleEmailAction(action: "send" | "draft", args: z.infer<typeof SendEmailSchema>) {
        const message = createEmailMessage(args);
        const encodedMessage = Buffer.from(message).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
        interface GmailMessageRequest { raw: string; threadId?: string; inReplyTo?: string; } // Add inReplyTo
        const messageRequest: GmailMessageRequest = { raw: encodedMessage };
        if (args.threadId) { messageRequest.threadId = args.threadId; }
        // Add In-Reply-To and References headers if inReplyTo is provided
        // Note: createEmailMessage needs modification to include these headers properly based on inReplyTo
        if (args.inReplyTo) {
            // This part needs modification in createEmailMessage to add correct headers
            logger.warn("In-Reply-To handling needs adjustment in createEmailMessage");
        }


        if (action === "send") {
            const response = await gmail.users.messages.send({ userId: 'me', requestBody: messageRequest });
            return { content: [{ type: "text" as const, text: `Email sent successfully with ID: ${response.data.id}` }] };
        } else {
            const response = await gmail.users.drafts.create({ userId: 'me', requestBody: { message: messageRequest } });
            return { content: [{ type: "text" as const, text: `Email draft created successfully with ID: ${response.data.id}` }] };
        }
    }

    // --- Helper function for batch processing ---
    async function processBatches<T, U>(
        items: T[],
        batchSize: number,
        processFn: (batch: T[]) => Promise<U[]>
    ): Promise<{ successes: U[], failures: { item: T, error: Error }[] }> {
        const successes: U[] = [];
        const failures: { item: T, error: Error }[] = [];
        for (let i = 0; i < items.length; i += batchSize) {
            const batch = items.slice(i, i + batchSize);
            try {
                const results = await processFn(batch);
                successes.push(...results);
            } catch (error) {
                logger.error({ error, batchIndex: i }, `Batch failed (index ${i})`);
                // If batch fails, try individual items
                for (const item of batch) {
                    try {
                        const result = await processFn([item]); // Process as a batch of one
                        successes.push(...result);
                    } catch (itemError) {
                        logger.error({ item, error: itemError }, `Item failed within batch`);
                        failures.push({ item, error: itemError as Error });
                    }
                }
            }
        }
        return { successes, failures };
    }

    // --- Register Tools using server.tool() following the example pattern ---

    server.tool("send_email",
        // Raw schema definition
        {
            to: z.array(z.string()).describe("List of recipient email addresses"),
            subject: z.string().describe("Email subject"),
            body: z.string().describe("Email body content"),
            cc: z.array(z.string()).optional().describe("List of CC recipients"),
            bcc: z.array(z.string()).optional().describe("List of BCC recipients"),
            threadId: z.string().optional().describe("Thread ID to reply to"),
            inReplyTo: z.string().optional().describe("Message ID being replied to"),
        },
        // Callback with single args parameter
        async (args) => {
            logger.info({ tool: 'send_email', args }, 'Handling send_email request');
            try {
                return await handleEmailAction("send", args);
            } catch (error: any) {
                logger.error({ tool: 'send_email', error, args }, 'Error sending email');
                return { content: [{ type: "text" as const, text: `Error sending email: ${error.message}` }], isError: true };
            }
        });

    server.tool("draft_email",
        // Raw schema definition
        {
            to: z.array(z.string()).describe("List of recipient email addresses"),
            subject: z.string().describe("Email subject"),
            body: z.string().describe("Email body content"),
            cc: z.array(z.string()).optional().describe("List of CC recipients"),
            bcc: z.array(z.string()).optional().describe("List of BCC recipients"),
            threadId: z.string().optional().describe("Thread ID to reply to"),
            inReplyTo: z.string().optional().describe("Message ID being replied to"),
        },
        // Callback with single args parameter
        async (args) => {
            logger.info({ tool: 'draft_email', args }, 'Handling draft_email request');
            try {
                return await handleEmailAction("draft", args);
            } catch (error: any) {
                logger.error({ tool: 'draft_email', error, args }, 'Error drafting email');
                return { content: [{ type: "text" as const, text: `Error drafting email: ${error.message}` }], isError: true };
            }
        });

    server.tool("read_email",
        // Raw schema definition
        {
            messageId: z.string().describe("ID of the email message to retrieve"),
        },
        // Callback with single destructured args parameter
        async ({ messageId }) => {
            logger.info({ tool: 'read_email', args: { messageId } }, 'Handling read_email request');
            try {
                const response = await gmail.users.messages.get({
                    userId: 'me',
                    id: messageId,
                    format: 'full', // Get full payload for content and attachments
                });

                const payload = response.data.payload;
                if (!payload) throw new Error("No payload found in message.");

                const headers = payload.headers || [];
                const subject = headers.find(h => h.name?.toLowerCase() === 'subject')?.value || '';
                const from = headers.find(h => h.name?.toLowerCase() === 'from')?.value || '';
                const to = headers.find(h => h.name?.toLowerCase() === 'to')?.value || '';
                const date = headers.find(h => h.name?.toLowerCase() === 'date')?.value || '';
                const threadId = response.data.threadId || '';

                const { text, html } = extractEmailContent(payload as GmailMessagePart);
                let body = text || html || ''; // Prefer text, fallback to html
                const contentTypeNote = !text && html ? '[Note: This email is HTML-formatted. Plain text version not available.]\n\n' : '';

                // Get attachment info
                const attachments: EmailAttachment[] = [];
                const processAttachmentParts = (part: GmailMessagePart) => {
                    if (part.body && part.body.attachmentId && part.filename) { // Ensure filename exists for attachments
                        attachments.push({
                            id: part.body.attachmentId,
                            filename: part.filename,
                            mimeType: part.mimeType || 'application/octet-stream',
                            size: part.body.size || 0
                        });
                    }
                    if (part.parts) {
                        part.parts.forEach(processAttachmentParts);
                    }
                };
                processAttachmentParts(payload as GmailMessagePart);

                const attachmentInfo = attachments.length > 0 ?
                    `\n\nAttachments (${attachments.length}):\n` +
                    attachments.map(a => `- ${a.filename} (${a.mimeType}, ${Math.round((a.size || 0) / 1024)} KB)`).join('\n') : '';

                return {
                    content: [{
                        type: "text" as const,
                        text: `Thread ID: ${threadId}\nSubject: ${subject}\nFrom: ${from}\nTo: ${to}\nDate: ${date}\n\n${contentTypeNote}${body}${attachmentInfo}`,
                    }],
                };
            } catch (error: any) {
                logger.error({ tool: 'read_email', error, args: { messageId } }, 'Error reading email');
                return { content: [{ type: "text" as const, text: `Error reading email: ${error.message}` }], isError: true };
            }
        });

    server.tool("search_emails",
        // Raw schema definition
        {
            query: z.string().describe(
                "Gmail search query (e.g., 'from:example@gmail.com'). " +
                "If you need to sort by date, use 'after:<date>'"
            ),
            maxResults: z.number().optional().describe("Maximum number of results to return"),
        },
        // Callback with single destructured args parameter
        async ({ query, maxResults }) => {
            logger.info({ tool: 'search_emails', args: { query, maxResults } }, 'Handling search_emails request');
            try {
                // --- Server-side fix: Remove 'sort:recent' --- 
                let processedQuery = query;
                const sortRecentRegex = /\s*sort:recent\s*/gi; 
                if (sortRecentRegex.test(processedQuery)) {
                    processedQuery = processedQuery.replace(sortRecentRegex, ' ').trim(); 
                    logger.warn({ tool: 'search_emails', originalQuery: query, processedQuery }, "Removed 'sort:recent' from query string.");
                }
                if (!processedQuery) {
                    logger.warn({ tool: 'search_emails', originalQuery: query }, "Query became empty after removing 'sort:recent', defaulting to 'in:inbox'.");
                    processedQuery = 'in:inbox'; 
                }
                // -----------------------------------------------

                const listResponse = await gmail.users.messages.list({
                    userId: 'me',
                    q: processedQuery, 
                    maxResults: maxResults || 10, // Use provided maxResults or default
                });

                const messages = listResponse.data.messages || [];
                logger.debug({ tool: 'search_emails', apiResponseCount: messages.length, estimatedResultCount: listResponse.data.resultSizeEstimate }, 'Gmail API list response received');

                if (messages.length === 0) {
                    return { content: [{ type: "text" as const, text: "No messages found matching the query." }] };
                }

                // --- Fetch details for each message ---
                let resultsText = `Found ${messages.length} messages:\n`;
                const messageDetailsPromises = messages.map(async (msg) => {
                    if (!msg.id) return null; // Skip if no ID
                    try {
                        const msgGetResponse = await gmail.users.messages.get({
                            userId: 'me',
                            id: msg.id,
                            format: 'metadata', // More efficient than 'full'
                            metadataHeaders: ['Subject', 'From', 'Date'] // Request specific headers
                        });

                        const headers = msgGetResponse.data.payload?.headers || [];
                        const subject = headers.find(h => h.name?.toLowerCase() === 'subject')?.value || 'No Subject';
                        const from = headers.find(h => h.name?.toLowerCase() === 'from')?.value || 'Unknown Sender';
                        const date = headers.find(h => h.name?.toLowerCase() === 'date')?.value || 'Unknown Date';

                        return `Message ID: ${msg.id}, From: ${from}, Date: ${date}, Subject: ${subject}`;
                    } catch (error) {
                        logger.error({ tool: 'search_emails', messageId: msg.id, error }, "Error getting metadata for message");
                        // Safely access error message
                        const errorMessage = error instanceof Error ? error.message : String(error);
                        return `Message ID: ${msg.id} - Error retrieving details: ${errorMessage}`; 
                    }
                });

                const messageDetails = await Promise.all(messageDetailsPromises);
                resultsText += messageDetails.filter(detail => detail !== null).join('\n');
                // ---------------------------------------

                return {
                    content: [{
                        type: "text" as const,
                        text: resultsText,
                    }],
                };
            } catch (error: any) {
                logger.error({ tool: 'search_emails', error, args: { query, maxResults } }, 'Error searching emails');
                return { content: [{ type: "text" as const, text: `Error searching emails: ${error.message}` }], isError: true };
            }
        });

    server.tool("modify_email",
        // Raw schema definition
        {
            messageId: z.string().describe("ID of the email message to modify"),
            labelIds: z.array(z.string()).optional().describe("[Deprecated] Use addLabelIds instead"),
            addLabelIds: z.array(z.string()).optional().describe("List of label IDs to add to the message"),
            removeLabelIds: z.array(z.string()).optional().describe("List of label IDs to remove from the message"),
        },
        // Callback with single args parameter
        async (args) => {
            logger.info({ tool: 'modify_email', args }, 'Handling modify_email request');
            try {
                const requestBody: { addLabelIds?: string[]; removeLabelIds?: string[] } = {};
                // Prefer addLabelIds/removeLabelIds if provided, fallback to labelIds for adding only (legacy?)
                if (args.addLabelIds && args.addLabelIds.length > 0) {
                    requestBody.addLabelIds = args.addLabelIds;
                } else if (args.labelIds && args.labelIds.length > 0) {
                    logger.warn({ tool: 'modify_email', args }, "Using deprecated 'labelIds' for adding labels in modify_email. Prefer 'addLabelIds'.");
                    requestBody.addLabelIds = args.labelIds;
                }

                if (args.removeLabelIds && args.removeLabelIds.length > 0) {
                    requestBody.removeLabelIds = args.removeLabelIds;
                }

                if (!requestBody.addLabelIds && !requestBody.removeLabelIds) {
                    throw new Error("No labels provided to add or remove.");
                }

                await gmail.users.messages.modify({
                    userId: 'me',
                    id: args.messageId,
                    requestBody: requestBody,
                });
                return { content: [{ type: "text" as const, text: `Email ${args.messageId} labels updated successfully` }] };
            } catch (error: any) {
                logger.error({ tool: 'modify_email', error, args }, 'Error modifying email');
                return { content: [{ type: "text" as const, text: `Error modifying email: ${error.message}` }], isError: true };
            }
        });

    server.tool("delete_email",
        // Raw schema definition
        {
            messageId: z.string().describe("The ID of the email to delete")
        },
        // Callback with single destructured args parameter
        async ({ messageId }) => {
            logger.info({ tool: 'delete_email', args: { messageId } }, 'Handling delete_email request');
            try {
                await gmail.users.messages.delete({ userId: 'me', id: messageId });
                return { content: [{ type: "text" as const, text: `Email ${messageId} deleted successfully` }] };
            } catch (error: any) {
                logger.error({ tool: 'delete_email', error, args: { messageId } }, 'Error deleting email');
                return { content: [{ type: "text" as const, text: `Error deleting email: ${error.message}` }], isError: true };
            }
        });

    server.tool("list_email_labels",
        // Raw schema definition (empty object for no args)
        {},
        // Callback with single (unused) args parameter
        async (_args) => {
            logger.info({ tool: 'list_email_labels', args: {} }, 'Handling list_email_labels request');
            try {
                const labelResults = await listLabels(gmail);
                const systemLabels = labelResults.system;
                const userLabels = labelResults.user;

                let text = `Found ${labelResults.count.total} labels (${labelResults.count.system} system, ${labelResults.count.user} user):\n\n`;
                if (systemLabels.length > 0) {
                    text += "System Labels:\n" + systemLabels.map((l: GmailLabel) => `- ${l.name} (ID: ${l.id})`).join('\n') + "\n\n";
                }
                if (userLabels.length > 0) {
                    text += "User Labels:\n" + userLabels.map((l: GmailLabel) => `- ${l.name} (ID: ${l.id})`).join('\n');
                }
                return { content: [{ type: "text" as const, text: text.trim() }] };
            } catch (error: any) {
                logger.error({ tool: 'list_email_labels', error, args: {} }, 'Error listing labels');
                return { content: [{ type: "text" as const, text: `Error listing labels: ${error.message}` }], isError: true };
            }
        });

    server.tool("batch_modify_emails",
        // Raw schema definition
        {
            messageIds: z.array(z.string()).describe("Array of message IDs to modify"),
            addLabelIds: z.array(z.string()).optional().describe("Labels to add to the messages"),
            removeLabelIds: z.array(z.string()).optional().describe("Labels to remove from the messages"),
            batchSize: z.number().optional().describe("Number of messages to process in each batch")
        },
        // Callback with single args parameter
        async (args) => {
            logger.info({ tool: 'batch_modify_emails', args }, 'Handling batch_modify_emails request');
            try {
                const requestBody: { addLabelIds?: string[]; removeLabelIds?: string[] } = {};
                if (args.addLabelIds) requestBody.addLabelIds = args.addLabelIds;
                if (args.removeLabelIds) requestBody.removeLabelIds = args.removeLabelIds;

                if (!requestBody.addLabelIds && !requestBody.removeLabelIds) {
                    throw new Error("No labels provided to add or remove in batch.");
                }

                const { successes, failures } = await processBatches(
                    args.messageIds,
                    args.batchSize || 50,
                    async (batch) => {
                        // Use batchModify instead of individual modify for efficiency
                        const res = await gmail.users.messages.batchModify({
                            userId: 'me',
                            requestBody: {
                                ids: batch, // Process the whole batch at once
                                ...(requestBody.addLabelIds && { addLabelIds: requestBody.addLabelIds }),
                                ...(requestBody.removeLabelIds && { removeLabelIds: requestBody.removeLabelIds }),
                            }
                        });
                        // Note: batchModify doesn't return per-message success/failure easily,
                        // so we assume success for the batch if no error is thrown.
                        // More granular error handling might require checking individual message states after.
                        return batch.map(id => ({ messageId: id, success: true }));
                    }
                );

                let resultText = `Batch label modification complete.\n`;
                resultText += `Attempted: ${args.messageIds.length} messages.\n`;
                resultText += `Batches resulting in success (may include individual failures not reported by API): ${successes.length}\n`; // Adjust reporting based on batchModify behavior
                if (failures.length > 0) {
                    resultText += `Batches/Items resulting in failure: ${failures.length}\n`;
                    resultText += `Failed item IDs/Errors (first few shown):\n`;
                    resultText += failures.slice(0, 5).map(f => `- Item: ${JSON.stringify(f.item)}, Error: ${f.error.message}`).join('\n');
                }

                return { content: [{ type: "text" as const, text: resultText }] };
            } catch (error: any) {
                logger.error({ tool: 'batch_modify_emails', error, args }, 'Error in batch modify');
                return { content: [{ type: "text" as const, text: `Error in batch modify: ${error.message}` }], isError: true };
            }
        });

    server.tool("batch_delete_emails",
        // Raw schema definition
        {
            messageIds: z.array(z.string()).describe("Array of message IDs to delete"),
            batchSize: z.number().optional().describe("Number of messages to process in each batch")
        },
        // Callback with single args parameter
        async (args) => {
            logger.info({ tool: 'batch_delete_emails', args }, 'Handling batch_delete_emails request');
            try {
                const { successes, failures } = await processBatches(
                    args.messageIds,
                    args.batchSize || 50,
                    async (batch) => {
                        await gmail.users.messages.batchDelete({
                            userId: 'me',
                            requestBody: {
                                ids: batch,
                            }
                        });
                        // Assume success if no error
                        return batch.map(id => ({ messageId: id, success: true }));
                    }
                );

                let resultText = `Batch delete operation complete.\n`;
                resultText += `Attempted: ${args.messageIds.length} messages.\n`;
                resultText += `Batches resulting in success (individual failures not reported): ${successes.length}\n`;
                if (failures.length > 0) {
                    resultText += `Batches/Items resulting in failure: ${failures.length}\n`;
                    resultText += `Failed item IDs/Errors (first few shown):\n`;
                    resultText += failures.slice(0, 5).map(f => `- Item: ${JSON.stringify(f.item)}, Error: ${f.error.message}`).join('\n');
                }

                return { content: [{ type: "text" as const, text: resultText }] };
            } catch (error: any) {
                logger.error({ tool: 'batch_delete_emails', error, args }, 'Error in batch delete');
                return { content: [{ type: "text" as const, text: `Error in batch delete: ${error.message}` }], isError: true };
            }
        });

    server.tool("create_label",
        // Raw schema definition
        {
            name: z.string().describe("The name of the label to create"),
            messageListVisibility: z.string().optional().describe("The visibility of the label in the message list"),
            labelListVisibility: z.string().optional().describe("The visibility of the label in the label list")
        },
        // Callback with single args parameter
        async (args) => {
            logger.info({ tool: 'create_label', args }, 'Handling create_label request');
            try {
                const result = await createLabel(gmail, args.name, {
                    messageListVisibility: args.messageListVisibility,
                    labelListVisibility: args.labelListVisibility,
                });
                return { content: [{ type: "text" as const, text: `Label created successfully:\nID: ${result.id}\nName: ${result.name}\nType: ${result.type}` }] };
            } catch (error: any) {
                logger.error({ tool: 'create_label', error, args }, 'Error creating label');
                return { content: [{ type: "text" as const, text: `Error creating label: ${error.message}` }], isError: true };
            }
        });

    server.tool("update_label",
        // Raw schema definition
        {
            id: z.string().describe("The ID of the label to update"),
            name: z.string().optional().describe("The new name for the label"),
            messageListVisibility: z.string().optional().describe("The visibility of the label in the message list"),
            labelListVisibility: z.string().optional().describe("The visibility of the label in the label list")
        },
        // Callback with single args parameter
        async (args) => {
            logger.info({ tool: 'update_label', args }, 'Handling update_label request');
            try {
                const updates: Partial<GmailLabel> = {}; // Use partial type
                if (args.name) updates.name = args.name;
                if (args.messageListVisibility) updates.messageListVisibility = args.messageListVisibility;
                if (args.labelListVisibility) updates.labelListVisibility = args.labelListVisibility;

                if (Object.keys(updates).length === 0) {
                    throw new Error("No update fields provided for the label.");
                }

                const result = await updateLabel(gmail, args.id, updates);
                return { content: [{ type: "text" as const, text: `Label updated successfully:\nID: ${result.id}\nName: ${result.name}\nType: ${result.type}` }] };
            } catch (error: any) {
                logger.error({ tool: 'update_label', error, args }, 'Error updating label');
                return { content: [{ type: "text" as const, text: `Error updating label: ${error.message}` }], isError: true };
            }
        });

    server.tool("delete_label",
        // Raw schema definition
        {
            id: z.string().describe("The ID of the label to delete")
        },
        // Callback with single destructured args parameter
        async ({ id }) => {
            logger.info({ tool: 'delete_label', args: { id } }, 'Handling delete_label request');
            try {
                const result = await deleteLabel(gmail, id);
                return { content: [{ type: "text" as const, text: result.message }] }; // deleteLabel returns { message: string }
            } catch (error: any) {
                logger.error({ tool: 'delete_label', error, args: { id } }, 'Error deleting label');
                return { content: [{ type: "text" as const, text: `Error deleting label: ${error.message}` }], isError: true };
            }
        });

    server.tool("get_or_create_label",
        // Raw schema definition
        {
            name: z.string().describe("The name of the label to get or create"),
            messageListVisibility: z.string().optional().describe("The visibility of the label in the message list"),
            labelListVisibility: z.string().optional().describe("The visibility of the label in the label list")
        },
        // Callback with single args parameter
        async (args) => {
            logger.info({ tool: 'get_or_create_label', args }, 'Handling get_or_create_label request');
            try {
                const result = await getOrCreateLabel(gmail, args.name, {
                    messageListVisibility: args.messageListVisibility,
                    labelListVisibility: args.labelListVisibility,
                });
                const action = result.created ? 'created new' : 'found existing'; // Use 'created' flag from getOrCreateLabel
                return { content: [{ type: "text" as const, text: `Successfully ${action} label:\nID: ${result.label.id}\nName: ${result.label.name}\nType: ${result.label.type}` }] };
            } catch (error: any) {
                logger.error({ tool: 'get_or_create_label', error, args }, 'Error getting or creating label');
                return { content: [{ type: "text" as const, text: `Error getting or creating label: ${error.message}` }], isError: true };
            }
        });

    const app = express();
    app.use(express.json());
    const port = process.env.PORT || 3000;
    const transports: { [sessionId: string]: StreamableHTTPServerTransport } = {};
    app.all('/mcp', async (req: Request, res: Response) => {
        const sessionId = req.headers['mcp-session-id'] as string | undefined;
        let transport: StreamableHTTPServerTransport;
        if (sessionId && transports[sessionId]) {
            transport = transports[sessionId];
        } else if (!sessionId && req.method === 'POST' && isInitializeRequest(req.body)) {
            transport = new StreamableHTTPServerTransport({
                sessionIdGenerator: randomUUID,
                onsessioninitialized: (newSessionId) => { transports[newSessionId] = transport; },
            });
            transport.onclose = () => { if (transport.sessionId) delete transports[transport.sessionId]; };
            await server.connect(transport);
        } else {
            res.status(400).json({ error: 'Bad Request' });
            return;
        }
        try {
            const requestBody = req.method === 'POST' ? req.body : undefined;
            await transport.handleRequest(req, res, requestBody);
        } catch (error) {
            logger.error({ error, sessionId: transport.sessionId }, `Error handling MCP request for session ${transport.sessionId}`);
            if (!res.headersSent) res.status(500).json({ error: 'Internal server error' });
        }
    });
    app.listen(port, () => {
        logger.info(`Gmail MCP Server (Stateful Streamable HTTP) listening on port ${port}, endpoint /mcp`);
    });
}

main().catch((error) => {
    logger.error({ error }, 'Server fatal error');
    process.exit(1);
});