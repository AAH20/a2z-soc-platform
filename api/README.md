# A2Z SOC API

The A2Z SOC API provides programmatic access to the A2Z Security Operations Center platform's data and features, including InfoSec Audits and AI Insights.

## Getting Started

### Prerequisites

- Node.js (v16 or higher)
- npm (v7 or higher)

### Installation

```bash
# Navigate to the API directory
cd api

# Install dependencies
npm install

# Start the development server
npm run dev
```

The API will be available at http://localhost:3000/api/v1/

## API Documentation

### Authentication

All API endpoints require authentication via an API key. Include your API key in the request headers:

```
x-api-key: YOUR_API_KEY
```

For development purposes, a test API key is automatically generated when running in non-production environments. This key will be displayed in the console when starting the server.

### Available Endpoints

#### InfoSec Audits

- `GET /api/v1/audits` - Get all compliance frameworks
- `GET /api/v1/audits/summary` - Get compliance summary statistics
- `GET /api/v1/audits/:id` - Get a specific compliance framework by ID
- `GET /api/v1/audits/:id/controls` - Get all controls for a specific framework
- `GET /api/v1/audits/:frameworkId/controls/:controlId` - Get a specific control from a framework

#### AI Insights

- `GET /api/v1/ai-insights/overview` - Get AI insights overview dashboard data
- `GET /api/v1/ai-insights/insights` - Get all AI-generated insights
- `GET /api/v1/ai-insights/insights/:id` - Get a specific AI insight by ID
- `GET /api/v1/ai-insights/recommendations` - Get all AI recommendations
- `GET /api/v1/ai-insights/coverage` - Get MITRE ATT&CK coverage data
- `GET /api/v1/ai-insights/trends` - Get analytics trend data
- `GET /api/v1/ai-insights/models` - Get AI model configurations
- `GET /api/v1/ai-insights/log-processing` - Get log processing status

#### Google Threat Intelligence

- `GET /api/v1/threat-intelligence/virustotal/health` - Check VirusTotal API health
- `GET /api/v1/threat-intelligence/virustotal/search` - Search for an indicator in VirusTotal
- `GET /api/v1/threat-intelligence/virustotal/file/:hash` - Get file report from VirusTotal
- `GET /api/v1/threat-intelligence/virustotal/url` - Get URL report from VirusTotal
- `GET /api/v1/threat-intelligence/virustotal/ip/:ip` - Get IP report from VirusTotal
- `GET /api/v1/threat-intelligence/virustotal/domain/:domain` - Get domain report from VirusTotal
- `GET /api/v1/threat-intelligence/google-scc/alerts` - Get Google Security Command Center alerts
- `GET /api/v1/threat-intelligence/mandiant` - Get Mandiant threat intelligence

### Authentication Management

- `POST /api/v1/auth/api-keys` - Generate a new API key (requires admin permission)
- `GET /api/v1/auth/verify` - Validate an API key
- `GET /api/v1/auth/api-keys` - Get all API keys (requires admin permission)
- `DELETE /api/v1/auth/api-keys/:name` - Revoke an API key by name (requires admin permission)

## RapidAPI Integration

This API is designed to be easily published on RapidAPI. The documentation for RapidAPI is available in the `docs/rapidapi-spec.js` file.

### Publishing to RapidAPI

1. Create an account on [RapidAPI](https://rapidapi.com/)
2. Navigate to the [Provider Dashboard](https://rapidapi.com/provider)
3. Click "Add new API"
4. Follow the prompts to add your API
5. Upload the documentation from `docs/rapidapi-spec.js`
6. Set up pricing tiers according to the documentation

## Development

### Project Structure

```
api/
├── config/         # Configuration files
├── controllers/    # Controller logic
├── docs/           # API documentation
├── middleware/     # Middleware functions
├── models/         # Data models
├── routes/         # Route definitions
├── utils/          # Utility functions
├── index.js        # Entry point
├── package.json    # Dependencies
└── README.md       # This file
```

### Running Tests

```bash
npm test
```

## Production Deployment

For production deployment, consider the following:

1. Set up a database for storing API keys and other data
2. Configure environment variables for sensitive information
3. Set up proper logging and monitoring
4. Deploy behind a reverse proxy with SSL/TLS

## License

This project is licensed under the MIT License. 