/**
 * PCAP/pcapng format detection and conversion utilities.
 *
 * mmt-dpi cannot extract TCP/UDP attributes from LINUX_SLL (Linux cooked v1)
 * encapsulation — only IP-level attributes work. This module detects LINUX_SLL
 * in both classic pcap and pcapng files, and converts them to standard Ethernet
 * (EN10MB) format using tcprewrite before handing them off to mmt_security.
 */

'use strict';

const fs = require('fs');
const path = require('path');
const { promisify } = require('util');
const { exec, execSync } = require('child_process');

const execAsync = promisify(exec);

// Warn once at startup if tcprewrite is missing so the problem is visible immediately
try {
  execSync('which tcprewrite', { stdio: 'ignore' });
} catch (_) {
  console.warn('[pcap-preprocess] WARNING: tcprewrite not found. LINUX_SLL PCAPs cannot be converted to Ethernet and rule-based detection will produce no results for such files. Install tcpreplay: apt-get install tcpreplay');
}

// Classic pcap global header magic numbers
const MAGIC_LE    = 0xa1b2c3d4;   // little-endian, microsecond timestamps
const MAGIC_LE_NS = 0xa1b23c4d;   // little-endian, nanosecond timestamps
const MAGIC_BE    = 0xd4c3b2a1;   // big-endian, microsecond timestamps
const MAGIC_BE_NS = 0x4d3cb2a1;   // big-endian, nanosecond timestamps

// pcapng
const PCAPNG_MAGIC   = 0x0a0d0d0a; // Section Header Block type (same in both endians)
const PCAPNG_BOM_LE  = 0x1a2b3c4d; // byte-order magic → file is little-endian
const PCAPNG_IDB_TYPE = 0x00000001; // Interface Description Block type

const LINUX_SLL_LINK_TYPE = 113;   // LINKTYPE_LINUX_SLL
const ETHERNET_LINK_TYPE  = 1;     // LINKTYPE_ETHERNET (EN10MB)

/**
 * Parse a pcapng file and return the link-layer type from the first
 * Interface Description Block (IDB).
 *
 * pcapng layout:
 *   SHB: [type(4)] [block_len(4)] [byte_order_magic(4)] [ver_maj(2)] [ver_min(2)]
 *        [section_len(8)] [options…] [block_len(4)]
 *   IDB: [type(4)] [block_len(4)] [link_type(2)] [reserved(2)] [snaplen(4)] …
 *
 * @param {number} fd - Open file descriptor
 * @returns {number|null}
 */
function getPcapngLinkType(fd) {
  // Read the first 12 bytes of the SHB to get block_len and byte-order magic
  const shbHead = Buffer.alloc(12);
  if (fs.readSync(fd, shbHead, 0, 12, 0) < 12) return null;

  // Byte-order magic is at offset 8; try both interpretations
  const bomLE = shbHead.readUInt32LE(8);
  const bomBE = shbHead.readUInt32BE(8);

  let littleEndian;
  if (bomLE === PCAPNG_BOM_LE) {
    littleEndian = true;
  } else if (bomBE === PCAPNG_BOM_LE) {
    littleEndian = false;
  } else {
    return null; // Malformed pcapng
  }

  const readU32 = (buf, off) => littleEndian ? buf.readUInt32LE(off) : buf.readUInt32BE(off);
  const readU16 = (buf, off) => littleEndian ? buf.readUInt16LE(off) : buf.readUInt16BE(off);

  // SHB total length is at offset 4
  const shbLen = readU32(shbHead, 4);
  if (shbLen < 28 || shbLen > 0x10000) return null; // Sanity check

  // The IDB immediately follows the SHB
  const idbOffset = shbLen;
  const idbHead = Buffer.alloc(12);
  if (fs.readSync(fd, idbHead, 0, 12, idbOffset) < 12) return null;

  const idbType = readU32(idbHead, 0);
  if (idbType !== PCAPNG_IDB_TYPE) return null; // Expected IDB

  // Link type is a uint16 at IDB offset 8
  return readU16(idbHead, 8);
}

/**
 * Read the link-layer type from a classic pcap or pcapng file.
 * Returns the numeric link type, or null if the format is unrecognised.
 */
function getPcapLinkType(filePath) {
  let fd;
  try {
    fd = fs.openSync(filePath, 'r');

    // Read the first 24 bytes (enough for classic pcap header)
    const header = Buffer.alloc(24);
    if (fs.readSync(fd, header, 0, 24, 0) < 24) return null;

    const magic = header.readUInt32LE(0);

    // pcapng: Section Header Block starts with 0x0a0d0d0a
    if (magic === PCAPNG_MAGIC) {
      return getPcapngLinkType(fd);
    }

    // Classic pcap: link type at bytes 20-23
    if (magic === MAGIC_LE || magic === MAGIC_LE_NS) {
      return header.readUInt32LE(20);
    }
    if (magic === MAGIC_BE || magic === MAGIC_BE_NS) {
      return header.readUInt32BE(20);
    }

    return null; // Unrecognised format
  } catch (_) {
    return null;
  } finally {
    if (fd !== undefined) {
      try { fs.closeSync(fd); } catch (_) {}
    }
  }
}

/**
 * Return true if the PCAP/pcapng uses LINUX_SLL encapsulation.
 */
function isLinuxSll(filePath) {
  return getPcapLinkType(filePath) === LINUX_SLL_LINK_TYPE;
}

/**
 * Convert a LINUX_SLL PCAP/pcapng to Ethernet format using tcprewrite.
 * The converted file is written to `outputDir` (defaults to the same
 * directory as the input file).
 *
 * @param {string} inputPath   - Absolute path to the source file
 * @param {string} [outputDir] - Directory for the converted file (optional)
 * @returns {Promise<string>}  - Absolute path to the converted file
 * @throws if tcprewrite is not found or conversion fails
 */
async function convertSllToEthernet(inputPath, outputDir) {
  const ext = path.extname(inputPath) || '.pcap';
  const base = path.basename(inputPath, ext);
  const destDir = outputDir || path.dirname(inputPath);
  const convertedPath = path.join(destDir, `${base}_eth${ext}`);

  const cmd = `tcprewrite --dlt=enet --enet-dmac=00:00:00:00:00:01 --enet-smac=00:00:00:00:00:02 --infile="${inputPath}" --outfile="${convertedPath}"`;
  await execAsync(cmd);
  return convertedPath;
}

/**
 * If the file at `inputPath` uses LINUX_SLL, convert it to Ethernet and
 * return { path: <converted path>, converted: true }.  Otherwise return
 * { path: inputPath, converted: false }.
 *
 * @param {string} inputPath   - Absolute path to the source file
 * @param {string} [outputDir] - Directory for converted file (optional)
 * @returns {Promise<{ path: string, converted: boolean, linkType: number|null }>}
 */
async function ensureEthernetPcap(inputPath, outputDir) {
  const linkType = getPcapLinkType(inputPath);
  if (linkType === LINUX_SLL_LINK_TYPE) {
    const convertedPath = await convertSllToEthernet(inputPath, outputDir);
    return { path: convertedPath, converted: true, linkType };
  }
  return { path: inputPath, converted: false, linkType };
}

module.exports = {
  getPcapLinkType,
  isLinuxSll,
  convertSllToEthernet,
  ensureEthernetPcap,
  LINUX_SLL_LINK_TYPE,
  ETHERNET_LINK_TYPE,
};
