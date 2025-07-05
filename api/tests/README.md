# A2Z SOC - Cloud Infrastructure Discovery Tests

This directory contains test scripts for verifying the agentless cloud discovery functionality of the A2Z SOC platform.

## Prerequisites

- Node.js installed
- API server running (locally or remotely)
- Cloud provider credentials (if you want to test against real cloud environments)

## Setup

1. Copy `env.test` to `.env` and update with your credentials:

```bash
cp env.test .env
```

2. Edit the `.env` file with your actual API key and cloud provider credentials

3. Install dependencies (if not already installed):

```bash
cd ../
npm install axios dotenv
```

## Running Tests

Run the test script with one of the following commands:

```bash
# Show help
node runTest.js help

# Test all cloud providers
node runTest.js all

# Test only AWS discovery
node runTest.js aws

# Test only Azure discovery
node runTest.js azure

# Test only Google Cloud discovery
node runTest.js gcp

# Test only credential verification
node runTest.js verify
```

## Test Structure

- `cloudInfraDiscovery.test.js` - Main test script with all test functions
- `runTest.js` - Command-line interface for running specific tests
- `env.test` - Template for environment variables

## Sample Output

When running tests, you'll see detailed information about the requests and responses for each API endpoint. For example:

```
--- Testing AWS Cloud Discovery ---

Testing health check...
Health check response: { success: true, timestamp: '2023-07-20T12:34:56.789Z', status: {...} }

Testing AWS EC2 instances discovery...
EC2 discovery response: { success: true, timestamp: '2023-07-20T12:34:56.789Z', data: [...] }
```

If there are any errors, they will be displayed with details to help with debugging.

## Using Tests in Development

These tests are useful for:

1. Verifying API endpoints are working correctly
2. Testing cloud provider integration
3. Debugging credential issues
4. Validating data structures returned by the API

## Notes

- By default, the tests will use placeholder credentials if real ones are not provided
- For security, avoid checking in your `.env` file with real credentials 