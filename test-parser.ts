import { existsSync, readFileSync, statSync } from 'fs';
import path from 'path';

async function run() {
  const filePath = path.join(process.cwd(), 'captures', 'Wifi.pcapng');
  if (!existsSync(filePath)) {
    console.error('Error: File not found', filePath);
    process.exit(1);
  }

  const buffer = readFileSync(filePath);
  const magic = buffer.readUInt32LE(0);
  console.log('Testing PCAP parser');
  console.log('File:', filePath);
  console.log('Size MB:', (statSync(filePath).size / 1024 / 1024).toFixed(2));
  console.log('Magic:', `0x${magic.toString(16)}`);
}

run().catch((err) => {
  console.error(err);
  process.exit(1);
});
