// Entry of the single executable build. Installs the asset patch first, then runs the CLI.
import './assets.cjs';
import '../../packages/cli/dist/index.js';
