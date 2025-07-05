const {
  testAwsDiscovery,
  testAzureDiscovery,
  testGcpDiscovery,
  testAllCloudResources,
  testCredentialVerification,
  runTests
} = require('./cloudInfraDiscovery.test');

const args = process.argv.slice(2);
const command = args[0]?.toLowerCase();

if (!command || command === 'help') {
  console.log(`
A2Z SOC Cloud Infrastructure Discovery Tester

Usage:
  node runTest.js [command]

Commands:
  all       Run all tests
  aws       Test AWS discovery
  azure     Test Azure discovery
  gcp       Test Google Cloud discovery
  verify    Test credential verification only
  help      Show this help message
  `);
  process.exit(0);
}

async function start() {
  try {
    switch (command) {
      case 'all':
        await runTests();
        break;
      case 'aws':
        await testAwsDiscovery();
        break;
      case 'azure':
        await testAzureDiscovery();
        break;
      case 'gcp':
        await testGcpDiscovery();
        break;
      case 'verify':
        await testCredentialVerification();
        break;
      default:
        console.error(`Unknown command: ${command}`);
        process.exit(1);
    }
  } catch (error) {
    console.error('Test failed:', error);
    process.exit(1);
  }
}

start(); 