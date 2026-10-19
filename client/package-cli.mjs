#!/usr/bin/env node
// Load the MCP dependencies only when a stdio MCP client requests them.
if(process.argv[2]==='mcp'){
 const {main}=await import('./accounts-mcp.mjs');
 await main().catch(()=>{process.stderr.write('ActAs MCP could not start. Check the private connection file and permissions.\n');process.exitCode=1;});
}else{
 await import('./public-cli.mjs');
}
