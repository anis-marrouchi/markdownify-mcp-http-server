import { ToolSchema } from "@modelcontextprotocol/sdk/types.js";

export const YouTubeToMarkdownTool = ToolSchema.parse({
  name: "youtube-to-markdown",
  description:
    "Convert a YouTube video to markdown, including transcript if available",
  inputSchema: {
    type: "object",
    properties: {
      url: {
        type: "string",
        description: "URL of the YouTube video",
      },
    },
    required: ["url"],
  },
});

export const PDFToMarkdownTool = ToolSchema.parse({
  name: "pdf-to-markdown",
  description: "Convert a PDF file to markdown. Use 'url' for online PDF files, or 'filepath' only if the file exists on the server. For local files, upload them first via /upload endpoint.",
  inputSchema: {
    type: "object",
    properties: {
      filepath: {
        type: "string",
        description: "Server-side absolute path of the PDF file (file must exist on the server filesystem)",
      },
      url: {
        type: "string", 
        description: "URL of the PDF file to download and convert (recommended for remote files)",
      },
    },
    oneOf: [
      { required: ["filepath"] },
      { required: ["url"] }
    ]
  },
});

export const BingSearchResultToMarkdownTool = ToolSchema.parse({
  name: "bing-search-to-markdown",
  description: "Convert a Bing search results page to markdown",
  inputSchema: {
    type: "object",
    properties: {
      url: {
        type: "string",
        description: "URL of the Bing search results page",
      },
    },
    required: ["url"],
  },
});

export const WebpageToMarkdownTool = ToolSchema.parse({
  name: "webpage-to-markdown",
  description: "Convert a webpage to markdown",
  inputSchema: {
    type: "object",
    properties: {
      url: {
        type: "string",
        description: "URL of the webpage to convert",
      },
    },
    required: ["url"],
  },
});

export const ImageToMarkdownTool = ToolSchema.parse({
  name: "image-to-markdown",
  description:
    "Convert an image to markdown, including metadata and description. Use 'url' for online image files, or 'filepath' only if the file exists on the server. For local files, upload them first via /upload endpoint.",
  inputSchema: {
    type: "object",
    properties: {
      filepath: {
        type: "string",
        description: "Server-side absolute path of the image file (file must exist on the server filesystem)",
      },
      url: {
        type: "string",
        description: "URL of the image file to download and convert (recommended for remote files)",
      },
    },
    oneOf: [
      { required: ["filepath"] },
      { required: ["url"] }
    ]
  },
});

export const AudioToMarkdownTool = ToolSchema.parse({
  name: "audio-to-markdown",
  description:
    "Convert an audio file to markdown, including transcription if possible. Use 'url' for online audio files, or 'filepath' only if the file exists on the server. For local files, upload them first via /upload endpoint.",
  inputSchema: {
    type: "object",
    properties: {
      filepath: {
        type: "string",
        description: "Server-side absolute path of the audio file (file must exist on the server filesystem)",
      },
      url: {
        type: "string",
        description: "URL of the audio file to download and convert (recommended for remote files)",
      },
    },
    oneOf: [
      { required: ["filepath"] },
      { required: ["url"] }
    ]
  },
});

export const DocxToMarkdownTool = ToolSchema.parse({
  name: "docx-to-markdown",
  description: "Convert a DOCX file to markdown. Use 'url' for online DOCX files, or 'filepath' only if the file exists on the server. For local files, upload them first via /upload endpoint.",
  inputSchema: {
    type: "object",
    properties: {
      filepath: {
        type: "string",
        description: "Server-side absolute path of the DOCX file (file must exist on the server filesystem)",
      },
      url: {
        type: "string",
        description: "URL of the DOCX file to download and convert (recommended for remote files)",
      },
    },
    oneOf: [
      { required: ["filepath"] },
      { required: ["url"] }
    ]
  },
});

export const XlsxToMarkdownTool = ToolSchema.parse({
  name: "xlsx-to-markdown",
  description: "Convert an XLSX file to markdown. Use 'url' for online XLSX files, or 'filepath' only if the file exists on the server. For local files, upload them first via /upload endpoint.",
  inputSchema: {
    type: "object",
    properties: {
      filepath: {
        type: "string",
        description: "Server-side absolute path of the XLSX file (file must exist on the server filesystem)",
      },
      url: {
        type: "string",
        description: "URL of the XLSX file to download and convert (recommended for remote files)",
      },
    },
    oneOf: [
      { required: ["filepath"] },
      { required: ["url"] }
    ]
  },
});

export const PptxToMarkdownTool = ToolSchema.parse({
  name: "pptx-to-markdown",
  description: "Convert a PPTX file to markdown. Use 'url' for online PPTX files, or 'filepath' only if the file exists on the server. For local files, upload them first via /upload endpoint.",
  inputSchema: {
    type: "object",
    properties: {
      filepath: {
        type: "string",
        description: "Server-side absolute path of the PPTX file (file must exist on the server filesystem)",
      },
      url: {
        type: "string",
        description: "URL of the PPTX file to download and convert (recommended for remote files)",
      },
    },
    oneOf: [
      { required: ["filepath"] },
      { required: ["url"] }
    ]
  },
});

export const GetMarkdownFileTool = ToolSchema.parse({
  name: "get-markdown-file",
  description: "Get a markdown file by absolute file path (file must exist on the server filesystem)",
  inputSchema: {
    type: "object",
    properties: {
      filepath: {
        type: "string",
        description: "Server-side absolute path to markdown file",
      },
    },
    required: ["filepath"],
  },
});

export const UploadFileForConversionTool = ToolSchema.parse({
  name: "upload-file-for-conversion",
  description: "IMPORTANT: Use this tool when you need to convert a local file that doesn't exist on the server. This tool provides specific upload instructions and explains how to handle local files with remote servers.",
  inputSchema: {
    type: "object",
    properties: {
      tool_type: {
        type: "string",
        enum: ["pdf-to-markdown", "image-to-markdown", "audio-to-markdown", "docx-to-markdown", "xlsx-to-markdown", "pptx-to-markdown"],
        description: "The type of conversion tool to use after upload",
      },
      local_file_path: {
        type: "string",
        description: "The local file path that needs to be uploaded (for reference in instructions)",
      },
      reason: {
        type: "string",
        description: "Why file upload is needed (e.g., 'file is on local machine', 'file not accessible to server')",
        default: "Local file needs to be uploaded to remote server",
      },
  },
  required: ["tool_type"],
  },
});

export const SearchTool = ToolSchema.parse({
  name: "search",
  description:
    "Search Markdownify connector docs and previously shared guidance to learn how to use this server inside ChatGPT or via API.",
  inputSchema: {
    type: "object",
    properties: {
      query: {
        type: "string",
        description:
          "Natural language query describing the information you need about Markdownify.",
      },
    },
    required: ["query"],
    additionalProperties: false,
  },
});

export const FetchTool = ToolSchema.parse({
  name: "fetch",
  description:
    "Fetch a specific Markdownify connector document by id. Use ids returned by the search tool.",
  inputSchema: {
    type: "object",
    properties: {
      id: {
        type: "string",
        description: "Identifier from a Markdownify search result.",
      },
    },
    required: ["id"],
    additionalProperties: false,
  },
});

