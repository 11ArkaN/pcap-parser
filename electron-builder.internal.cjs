const path = require("path");
const pkg = require("./package.json");

const base = pkg.build || {};

module.exports = {
  ...base,
  directories: {
    ...(base.directories || {}),
    output: "release/internal"
  },
  productName: "PCAP Analyzer Internal",
  artifactName: "${productName}-Setup-${version}-internal.${ext}",
  nsis: {
    ...(base.nsis || {}),
    include: path.join("build", "installer.internal.nsh")
  }
};
