/** Records receipts as fast as it can until killed: the interrupted-capture test. */
import { openWorkspace } from "../../src/workspace.js";
import { recordReceipt } from "../../src/receipts.js";

const ws = openWorkspace(process.argv[2]!);
process.stdout.write("started\n");
for (let i = 0; ; i++) recordReceipt(ws, { capture: "cli", tool_name: "loop", target_resource: `item-${i}`, input: { i, pad: "x".repeat(2000) } });
