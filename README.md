# xbox_shrinker
This program will remove (scrub) the random padding found in (OG) xbox iso file. The iso files need to be in redump format.
The scrubbed iso is still fully functional and can be uses in emulators etc. Compressed scrubbed isos are usually several GB smaller than the unscrubbed counterparts.
The program also supports unscrubbing of the iso and reconstruction of the original file.

# Credits
* [LedZeppelin68](https://github.com/LedZeppelin68/dvd-shrinker) for his dvd_shrinker program. Especially for his implementation of the seed brute-forcer!
* [XboxDev](https://github.com/XboxDev/extract-xiso) for extract_xiso. Parts were used for the analysis of the iso layout.
