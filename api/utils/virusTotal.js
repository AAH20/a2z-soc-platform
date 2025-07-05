const axios = require('axios');
const keys = require('../config/keys');
const FormData = require('form-data');

// VirusTotal API base URL
const VT_API_BASE_URL = 'https://www.virustotal.com/api/v3';

/**
 * Create an axios instance for VirusTotal API calls
 */
const vtClient = axios.create({
  baseURL: VT_API_BASE_URL,
  headers: {
    'x-apikey': keys.virustotal.apiKey,
    'Content-Type': 'application/json'
  }
});

/**
 * Check the health of the VirusTotal API connection
 * @returns {Promise<boolean>} Whether the API connection is healthy
 */
const checkApiHealth = async () => {
  try {
    // Just making a simple call to test the API key and connectivity
    await vtClient.get('/users/current');
    return true;
  } catch (error) {
    console.error('VirusTotal API health check failed:', error.message);
    return false;
  }
};

/**
 * Search VirusTotal for a specific indicator
 * @param {string} query - The search query (IP, domain, file hash, etc.)
 * @param {string} type - Type of the query (ip, domain, file, url)
 * @returns {Promise<Object>} Search results from VirusTotal
 */
const searchIndicator = async (query, type) => {
  try {
    let endpoint;
    
    // Determine the appropriate endpoint based on the indicator type
    switch (type) {
      case 'ip':
        endpoint = `/ip_addresses/${query}`;
        break;
      case 'domain':
        endpoint = `/domains/${query}`;
        break;
      case 'file':
        // Assuming query is a file hash
        endpoint = `/files/${query}`;
        break;
      case 'url':
        // URL needs to be encoded and then base64 encoded
        const encodedUrl = Buffer.from(encodeURIComponent(query)).toString('base64');
        endpoint = `/urls/${encodedUrl}`;
        break;
      default:
        // Default to a general search
        const response = await vtClient.get('/search', {
          params: { query }
        });
        return response.data;
    }
    
    // Make the API call to the determined endpoint
    const response = await vtClient.get(endpoint);
    return response.data;
  } catch (error) {
    console.error(`VirusTotal search failed for ${type} ${query}:`, error.response?.data || error.message);
    throw new Error(`VirusTotal search failed: ${error.response?.data?.error?.message || error.message}`);
  }
};

/**
 * Get a file report from VirusTotal
 * @param {string} fileHash - The hash of the file (MD5, SHA-1, SHA-256)
 * @returns {Promise<Object>} File analysis report
 */
const getFileReport = async (fileHash) => {
  try {
    const response = await vtClient.get(`/files/${fileHash}`);
    return response.data;
  } catch (error) {
    console.error(`VirusTotal file report failed for ${fileHash}:`, error.response?.data || error.message);
    throw new Error(`VirusTotal file report failed: ${error.response?.data?.error?.message || error.message}`);
  }
};

/**
 * Get a URL report from VirusTotal
 * @param {string} url - The URL to analyze
 * @returns {Promise<Object>} URL analysis report
 */
const getUrlReport = async (url) => {
  try {
    // URL needs to be encoded and then base64 encoded for VirusTotal API
    const encodedUrl = Buffer.from(encodeURIComponent(url)).toString('base64');
    const response = await vtClient.get(`/urls/${encodedUrl}`);
    return response.data;
  } catch (error) {
    console.error(`VirusTotal URL report failed for ${url}:`, error.response?.data || error.message);
    throw new Error(`VirusTotal URL report failed: ${error.response?.data?.error?.message || error.message}`);
  }
};

/**
 * Get an IP address report from VirusTotal
 * @param {string} ip - The IP address to analyze
 * @returns {Promise<Object>} IP analysis report
 */
const getIpReport = async (ip) => {
  try {
    const response = await vtClient.get(`/ip_addresses/${ip}`);
    return response.data;
  } catch (error) {
    console.error(`VirusTotal IP report failed for ${ip}:`, error.response?.data || error.message);
    throw new Error(`VirusTotal IP report failed: ${error.response?.data?.error?.message || error.message}`);
  }
};

/**
 * Get a domain report from VirusTotal
 * @param {string} domain - The domain to analyze
 * @returns {Promise<Object>} Domain analysis report
 */
const getDomainReport = async (domain) => {
  try {
    const response = await vtClient.get(`/domains/${domain}`);
    return response.data;
  } catch (error) {
    console.error(`VirusTotal domain report failed for ${domain}:`, error.response?.data || error.message);
    throw new Error(`VirusTotal domain report failed: ${error.response?.data?.error?.message || error.message}`);
  }
};

/**
 * Get a URL for uploading large files to VirusTotal (>32MB, up to 650MB)
 * @returns {Promise<string>} URL for uploading large files
 */
const getLargeFileUploadUrl = async () => {
  try {
    const response = await vtClient.get('/files/upload_url');
    return response.data.data;
  } catch (error) {
    console.error('Failed to get upload URL for large file:', error.response?.data || error.message);
    throw new Error(`Failed to get upload URL: ${error.response?.data?.error?.message || error.message}`);
  }
};

/**
 * Upload a file to VirusTotal
 * @param {Buffer} fileBuffer - The file buffer to upload
 * @param {string} fileName - The name of the file
 * @returns {Promise<Object>} Upload response from VirusTotal
 */
const uploadFile = async (fileBuffer, fileName) => {
  try {
    const formData = new FormData();
    formData.append('file', fileBuffer, { filename: fileName });
    
    const response = await axios.post(`${VT_API_BASE_URL}/files`, formData, {
      headers: {
        'x-apikey': keys.virustotal.apiKey,
        ...formData.getHeaders()
      }
    });
    
    return response.data;
  } catch (error) {
    console.error(`VirusTotal file upload failed for ${fileName}:`, error.response?.data || error.message);
    throw new Error(`VirusTotal file upload failed: ${error.response?.data?.error?.message || error.message}`);
  }
};

module.exports = {
  checkApiHealth,
  searchIndicator,
  getFileReport,
  getUrlReport,
  getIpReport,
  getDomainReport,
  getLargeFileUploadUrl,
  uploadFile
}; 