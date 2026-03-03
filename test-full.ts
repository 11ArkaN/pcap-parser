import { readFileSync } from 'fs';
import { aggregateConnections } from './src/components/DataTable';
import { parsePcap } from './src/utils/pcapParser';

async function run() {
  const input = new Uint8Array(readFileSync('./captures/Wifi.pcapng'));
  const parsed = await parsePcap(input);
  const rows = aggregateConnections(parsed);

  console.log('Parsed packets:', parsed.length);
  console.log('Table rows:', rows.length);
  console.log('Total bytes:', rows.reduce((sum, row) => sum + row.bytes, 0));
}

run().catch((err) => {
  console.error(err);
  process.exit(1);
});
