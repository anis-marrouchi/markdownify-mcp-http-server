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
  description: "Convert a PDF file to markdown. For remote servers, use 'url' for remote files or upload files first using the upload endpoint.",
  inputSchema: {
    type: "object",
    properties: {
      filepath: {
        type: "string",
        description: "Absolute path of the PDF file (only works for local server access)",
      },
      url: {
        type: "string", 
        description: "URL of the PDF file to download and convert",
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
    "Convert an image to markdown, including metadata and description. For remote servers, use 'url' for remote files or upload files first using the upload endpoint.",
  inputSchema: {
    type: "object",
    properties: {
      filepath: {
        type: "string",
        description: "Absolute path of the image file (only works for local server access)",
      },
      url: {
        type: "string",
        description: "URL of the image file to download and convert",
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
    "Convert an audio file to markdown, including transcription if possible. For remote servers, use 'url' for remote files or upload files first using the upload endpoint.",
  inputSchema: {
    type: "object",
    properties: {
      filepath: {
        type: "string",
        description: "Absolute path of the audio file (only works for local server access)",
      },
      url: {
        type: "string",
        description: "URL of the audio file to download and convert",
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
  description: "Convert a DOCX file to markdown. For remote servers, use 'url' for remote files or upload files first using the upload endpoint.",
  inputSchema: {
    type: "object",
    properties: {
      filepath: {
        type: "string",
        description: "Absolute path of the DOCX file (only works for local server access)",
      },
      url: {
        type: "string",
        description: "URL of the DOCX file to download and convert",
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
  description: "Convert an XLSX file to markdown. For remote servers, use 'url' for remote files or upload files first using the upload endpoint.",
  inputSchema: {
    type: "object",
    properties: {
      filepath: {
        type: "string",
        description: "Absolute path of the XLSX file (only works for local server access)",
      },
      url: {
        type: "string",
        description: "URL of the XLSX file to download and convert",
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
  description: "Convert a PPTX file to markdown. For remote servers, use 'url' for remote files or upload files first using the upload endpoint.",
  inputSchema: {
    type: "object",
    properties: {
      filepath: {
        type: "string",
        description: "Absolute path of the PPTX file (only works for local server access)",
      },
      url: {
        type: "string",
        description: "URL of the PPTX file to download and convert",
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
  description: "Get a markdown file by absolute file path (only works for local server access)",
  inputSchema: {
    type: "object",
    properties: {
      filepath: {
        type: "string",
        description: "Absolute path to file of markdown'd text",
      },
    },
    required: ["filepath"],
  },
});

export const UploadAndConvertTool = ToolSchema.parse({
  name: "upload-and-convert",
  description: "Upload a file and convert it to markdown. This tool provides instructions for file upload when using a remote server.",
  inputSchema: {
    type: "object",
    properties: {
      tool_type: {
        type: "string",
        enum: ["pdf-to-markdown", "image-to-markdown", "audio-to-markdown", "docx-to-markdown", "xlsx-to-markdown", "pptx-to-markdown"],
        description: "The type of conversion tool to use after upload",
      },
      instructions: {
        type: "boolean",
        description: "Set to true to get upload instructions",
        default: true,
      },
    },
    required: ["tool_type"],
  },
});
