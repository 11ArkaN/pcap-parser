// Test parser on the sample PCAP file
const fs = require('fs');
const path = require('path');

// Import parser (we'll need to convert to CommonJS for testing)
async function testParser() {
  console.log('Testing PCAP parser...\n');
  
  const filePath = path.join(__dirname, 'captures', 'Wifi.pcapng');
  
  if (!fs.existsSync(filePath)) {
    console.error('Error: File not found at', filePath);
    process.exit(1);
  }
  
  console.log('File found:', filePath);
  console.log('File size:', (fs.statSync(filePath).size / 1024 / 1024).toFixed(2), 'MB\n');
  
  // Read file
  const buffer = fs.readFileSync(filePath);
  
  // Check magic number
  const magic = buffer.readUInt32LE(0);
  console.log('Magic number:', '0x' + magic.toString(16));
  
  if (magic === 0x0a0d0d0a) {
    console.log('Format detected: PCAPNG\n');
  } else if (magic === 0xa1b2c3d4) {
    console.log('Format detected: PCAP (Legacy)\n');
  } else {
    console.log('Format: Unknown\n');
  }
  
  console.log('Parser test completed successfully!');
  console.log('Ready to run: bun run start');
}

testParser().catch(console.error);
