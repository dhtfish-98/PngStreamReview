# Source and contribution record

Technical source: [pnggroup/pngcheck](https://github.com/pnggroup/pngcheck) at fixed commit `bd33ad6490269df07cac81e5305f4ebf56c2b637`. License: `MIT`; the original license text and original copyright notices are preserved.

New implementation author: **dhtfish98**. This project implements the explicitly selected standalone scope below. It is not presented as original ownership of the upstream algorithms or as a full rewrite of an upstream platform. No source files have merely been renamed into the runtime package.

Scope: Noninterlaced PNG signature, chunk boundaries/type bits/CRC, singleton and critical order, IHDR combinations, PLTE/tRNS constraints, bounded zlib stream length and scanline filter bytes.

The upstream entry points, format layouts and relevant default file/network/execution paths were inspected in the fixed files listed in SOURCE_MANIFEST.json. Complete new runtime files are reviewed separately; this does not imply audit of unselected upstream platform code.

Excluded upstream capabilities: Adam7, APNG, reconstruction of pixel values, nested text/profile decompression, MNG/JNG and full pngcheck equivalence.

The repository owner must verify their actual contribution and authorization before using this record in an application. No CVE, rejected-model task, CVP acceptance or personal identity evidence has been invented.
