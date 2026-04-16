#!/usr/bin/env node

const { Command } = require('commander');
const { spawn } = require('child_process');
const chalk = require('chalk');
const path = require('path');

const program = new Command();

program
  .name('network-scanner')
  .description('A professional Node.js CLI wrapper for a Python Network Port Scanner')
  .version('1.0.0');

program
  .command('scan')
  .description('Scan the local network for open ports')
  .option('-s, --start <port>', 'Starting port number', '1')
  .option('-e, --end <port>', 'Ending port number', '1024')
  .option('-j, --json', 'Output results in JSON format')
  .action((options) => {
    const startPort = options.start;
    const endPort = options.end;
    const isJson = options.json;

    if (!isJson) {
      console.log(chalk.cyan.bold('\n🚀 Starting Network Port Scanner...'));
      console.log(chalk.gray(`Range: ${startPort} - ${endPort}\n`));
    }

    const pythonProcess = spawn('python', [
      path.join(__dirname, 'network_scanner.py'),
      '--start', startPort,
      '--end', endPort,
      ...(isJson ? ['--json'] : [])
    ], {
      env: { ...process.env, PYTHONIOENCODING: 'utf-8' }
    });

    pythonProcess.stdout.on('data', (data) => {
      // Just pass through the output from Python
      process.stdout.write(data.toString());
    });

    pythonProcess.stderr.on('data', (data) => {
      console.error(chalk.red(`Error: ${data}`));
    });

    pythonProcess.on('close', (code) => {
      if (code !== 0) {
        if (!isJson) console.log(chalk.red(`\n❌ Python process exited with code ${code}`));
      } else {
        if (!isJson) console.log(chalk.green.bold('\n✅ Scan completed successfully.'));
      }
    });
  });

program.parse(process.argv);

if (!process.argv.slice(2).length) {
  program.outputHelp();
}
