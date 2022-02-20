using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.IO;
using System.Xml;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text.RegularExpressions;

/*

  todo: refactor mergearrays to create disjunct ranges (see padseccount) for cleaner code. write loop of iso can be simplified
  
*/


class xbox_shrinker
{
    static UInt32[] b_seeds =
    {
        0x52F690D5,
        0x534D7DDE,
        0x5B71A70F,
        0x66793320,
        0x9B7E5ED5,
        0xA465265E,
        0xA53F1D11,
        0xB154430F
    };
    static bool debug = false;
    const uint GP_OFFSET = 0x18300000;
    const int SECTOR_SIZE = 0x800;
    
    static void Main(string[] args)
    {
        if (args.Length == 0)
        {
            Console.WriteLine("Usage: xbox_shrinker.exe <isofile> [<rc4file>]");
            return;
        }
        /*
        test(args[0]);
        Environment.Exit(0);
        */
        byte[] junk = JunkBlock();
        string fileName = Path.GetFullPath(args[0]);
        //Console.WriteLine(fileName);
        if (!File.Exists(fileName))
        {
            Console.WriteLine("Error. File not found: " + fileName);
            Environment.Exit(0);
        }
        int version = getVersion(fileName);
        if (version == 0)
        {
            Console.WriteLine("Error. Invalid XBOX iso (maybe not in redump format?)");
            Environment.Exit(0);
        }
        else if ((version > 4808) && (version < 4830))
        {
            Console.WriteLine("Unknown Version: " + version.ToString());
            Environment.Exit(0);
        }
        bool seedflag = (version <= 4830);  //4808 Blade II (USA), 4830 NFL Fever 2003 (USA) (Beta)
        string ssxml = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "ss.xml");
        bool xml = File.Exists(ssxml);
        //Console.WriteLine(xml);
        string rc4file = Path.GetFullPath(args[0].Replace(".dec", ""));
        
        rc4file = rc4file.Replace(".iso", ".rc4");
        if (args.Length >= 2)
        {
            rc4file = Path.GetFullPath(args[1]);
        }

        MD5 hash = MD5.Create();
        UInt32 seed = 0;
        string rom_md5 = "";
        UInt32[,] security_sectors = new UInt32[16,2];
        //bool seedflag = false;
        bool xmlentry = false;
        bool seedEntry = false;

        uint[,] dtemp = getDataArray(fileName);
        uint firstjunksector = getfirstjunksector(dtemp);
        //Console.WriteLine(firstjunksector.ToString());
        //Environment.Exit(0);
        bool scrubbed = mode(fileName, junk, firstjunksector);      
        if (!scrubbed)   //get seed, md5, ssranges
        { 
            XmlDocument ssRanges = new XmlDocument();
            XmlNode rom_xml;
            if (xml)
            {
                ssRanges.Load(ssxml);
                rom_xml = ssRanges.DocumentElement.SelectSingleNode(string.Format("rom[@name=\"{0}\"]", Path.GetFileName(fileName)));
                if(rom_xml != null)
                {
                    xmlentry = true;
                    rom_md5 = rom_xml.Attributes["md5"].Value;
                    security_sectors = readSS(rom_xml.Attributes["ssrange"].Value);
                    if ( (rom_xml.Attributes["seed"].Value != string.Empty) && (rom_xml.Attributes["seed"].Value != "rc4"))
                    {
                        seed = Convert.ToUInt32(rom_xml.Attributes["seed"].Value, 16);
                        seedEntry = true;
                    }
                }
            }
            
            if (!xmlentry)
            {
                Console.Write("Calculating hash and getting Security Sector Ranges from iso... ");
                Tuple<uint[,], string> isoprops = getSS(fileName, hash);
                security_sectors = isoprops.Item1;
                rom_md5 = isoprops.Item2;
                Console.WriteLine("done");
            }
            
            if (seedflag && !seedEntry)
            {
                Console.Write("Starting Brute-Forcing seed... ");
                seed = bruteForceSeed(fileName);
                if (seed != 0)
                {
                    Console.WriteLine("Found! => 0x{0:x8}", seed);
                }
                
                else
                {
                    if ((version >= 4721) && (version < 5000))
                    {
                        Console.WriteLine("Brute-Force Failed for Version " + version.ToString() + ". Assuming rc4 algo.");
                        seedflag = false;
                    }
                    else
                    {
                        Console.WriteLine("Error. Brute-Force Failed!");
                        Environment.Exit(0);
                    }
                }
            }
            
            
            if (!xml)
            {
                //create ss.xml
                XmlElement root = ssRanges.DocumentElement;
                XmlElement datafile = ssRanges.CreateElement("datafile");
                ssRanges.AppendChild( datafile );
                ssRanges.Save( ssxml );
            }
            
            if (!seedEntry)
            {
                ssRanges.Load(ssxml);
                rom_xml = ssRanges.DocumentElement.SelectSingleNode(string.Format("rom[@name=\"{0}\"]", Path.GetFileName(fileName)));
                if (rom_xml == null)
                {
                    //make new entry
                    XmlNode datafile = ssRanges.DocumentElement.SelectSingleNode("/datafile");
                    XmlElement newrom = ssRanges.CreateElement("rom");
                    
                    XmlAttribute xmlname = ssRanges.CreateAttribute("name");
                    xmlname.Value = Path.GetFileName(fileName);
                    newrom.Attributes.Append(xmlname);
                    
                    XmlAttribute xmlmd5 = ssRanges.CreateAttribute("md5");
                    xmlmd5.Value = rom_md5;
                    newrom.Attributes.Append(xmlmd5);
                    
                    XmlAttribute xmlseed = ssRanges.CreateAttribute("seed");
                    if (seed != 0)
                    {
                        xmlseed.Value = seed.ToString("X").ToLower();
                    }
                    else
                    {
                        xmlseed.Value = "rc4";
                    }
                    newrom.Attributes.Append(xmlseed);
                    
                    string ssrangestr = string.Join(",",
                        Enumerable.Range(0, security_sectors.GetUpperBound(0) + 1)
                        .Select(x => Enumerable.Range(0, security_sectors.GetUpperBound(1) + 1)
                        .Select(y => security_sectors[x, y]))
                        .Select(z => string.Join(":", z)));
                    
                    XmlAttribute xmlssrange = ssRanges.CreateAttribute("ssrange");
                    xmlssrange.Value = ssrangestr;
                    newrom.Attributes.Append(xmlssrange);
                    datafile.AppendChild(newrom);
                }
                
                else
                {
                    ssRanges.Load(ssxml);
                    rom_xml = ssRanges.DocumentElement.SelectSingleNode(string.Format("rom[@name=\"{0}\"]", Path.GetFileName(fileName)));
                    if (seed != 0)
                    {
                        rom_xml.Attributes["seed"].Value = string.Format("{0:x8}", seed);
                    }
                    else
                    {
                        rom_xml.Attributes["seed"].Value = "rc4";
                    }
                }
                ssRanges.Save( ssxml );
            }
            
        }
        
        else  // get seed, md5, ssranges from scrubbed file
        { 
            using (BinaryReader br = new BinaryReader(new FileStream(fileName, FileMode.Open)))
            {
                br.BaseStream.Position = (long)firstjunksector * SECTOR_SIZE;
                seedflag = (br.ReadUInt32() == 1);
                seed = br.ReadUInt32();
                br.ReadUInt32();
                br.ReadUInt64(); // Optimistic reserved space for 128bit rc4 key
                rom_md5 = BitConverter.ToString(br.ReadBytes(16)).Replace("-","").ToLower();
                if (br.ReadUInt32() == 16)
                {
                    for ( int i = 0; i<16; i++)
                    {
                        security_sectors[i, 0] = br.ReadUInt32();
                        security_sectors[i, 1] = br.ReadUInt32();
                    }
                }
                else
                {
                    Console.WriteLine("ERROR. Number of security sectors not matching.");
                    Environment.Exit(0);
                }

            }

        }
        
        uint[,] dataranges = mergeArrays(dtemp, security_sectors);
        /*
        //uint[,] dataranges = new uint[12,2];
        Console.WriteLine("\nSS");
        for (int i = 0; i < security_sectors.GetLength(0); i++)
        {
            Console.WriteLine(security_sectors[i, 0].ToString() + " - " + security_sectors[i, 1].ToString());
        }            
        Console.WriteLine("\nData");
        for (int i = 0; i < dtemp.GetLength(0); i++)
        {
            Console.WriteLine(dtemp[i, 0].ToString() + " - " + dtemp[i, 1].ToString());
        }
        
                   
        Console.WriteLine("\nMerged");
        for (int i = 0; i < dataranges.GetLength(0); i++)
        {
            Console.WriteLine(dataranges[i, 0].ToString() + " - " + dataranges[i, 1].ToString());
        }
        Console.WriteLine("PadSec:   " + (getPadSecCount(dataranges)).ToString() + " Sectors  " + (getPadSecCount(dataranges)*0x800).ToString() + " Bytes");
        //Environment.Exit(0);
        */

        
        
        if (scrubbed && !seedflag)
        {
            if (!File.Exists(rc4file))
            {
                Console.WriteLine("Eror. File not found: " + rc4file);
                Environment.Exit(0);
            }
        }
        
        if (!scrubbed && !seedflag)
        {
            seed = getPadSecCount(dataranges);  // seed = Sectorcount of padding sectors
            //Console.WriteLine((seed*2048).ToString());
        }
        
        else if (scrubbed && !seedflag)
        {
            using (BinaryReader br = new BinaryReader(new FileStream(fileName, FileMode.Open)))
            {
                br.BaseStream.Position = (long)firstjunksector * SECTOR_SIZE;
                br.ReadUInt32();
                uint rc4headsec = br.ReadUInt32();
                long rc4head = (long)rc4headsec * SECTOR_SIZE;
                long rc4real = new System.IO.FileInfo(rc4file).Length;
            
                if (rc4head != rc4real)
                {
                    Console.WriteLine("Error: Filesize Mismatch for rc4 file!\nExpected: " + (rc4head).ToString() + " Bytes\nActual:   " + (rc4real).ToString() + " Bytes");
                    //Console.WriteLine("PadSec:   " + (getPadSecCount(dataranges)*0x800).ToString() + " Bytes");
                    Environment.Exit(0); 
                }
            }
        }
        //Console.WriteLine("Seed: " + seed.ToString());
        //Environment.Exit(0);
        string fileNameOut = string.Empty;
        
        if(scrubbed)
        {
            fileNameOut = fileName.Replace(".iso.dec", ".iso");
        }
        else
        {
            fileNameOut = fileName + ".dec";
        }

        if (scrubbed)
        {
            Console.WriteLine("starting reconstruction process... ");
        }
        else
        {
            Console.WriteLine("starting scrubbing process... ");
            if (!seedflag)
            {
                Console.WriteLine("  => " + rc4file);
            }
        }
        Console.WriteLine("  => " + fileNameOut);
        
        
        using (BinaryReader br = new BinaryReader(new FileStream(fileName, FileMode.Open)))
        {
            using (BinaryWriter bw = new BinaryWriter(new FileStream(fileNameOut, FileMode.OpenOrCreate)))
            {
                // Copy Video Partition
                while (br.BaseStream.Position < GP_OFFSET)
                {
                    byte[] tempBuffer = br.ReadBytes(SECTOR_SIZE);
                    if (scrubbed)  // !scrubbed hash already calculated with getSS
                    {
                        hash.TransformBlock(tempBuffer, 0, SECTOR_SIZE, null, 0);
                    }
                    bw.Write(tempBuffer);
                }
                if (scrubbed)
                {
                    byte[] randomSector = new byte[SECTOR_SIZE];
                    BinaryWriter rs = new BinaryWriter(new MemoryStream(randomSector));
                    if (seedflag)
                    {
                        if (firstjunksector != 198144)
                        {
                            Console.WriteLine("Functionality not yet implemented. Please open an issue when you get this error.");
                            Environment.Exit(0);
                        }
                        uint a_t = 0;
                        uint b_t = 0;
                        uint c_t = 0;
                        Seed(seed, ref a_t, ref b_t, ref c_t);
                        
                        for (int j = 0; j < SECTOR_SIZE; j += 2)
                        {
                            UInt16 sample = (UInt16)(Value(ref a_t, ref b_t, ref c_t) >> 8);
                            rs.Write(sample);
                        }
                        hash.TransformBlock(randomSector, 0, SECTOR_SIZE, null, 0);
                        
                        br.ReadBytes(SECTOR_SIZE);
                        bw.Write(randomSector);
                        
                        rs.BaseStream.Position = 0;
                        for (int j = 0; j < SECTOR_SIZE; j += 2)
                        {
                            UInt16 sample = (UInt16)(Value(ref a_t, ref b_t, ref c_t) >> 8);
                            rs.Write(sample);
                        }
                        
                        int currentrange = 0;
                        //while (br.BaseStream.Position < 0x1F400000)
                        while (br.BaseStream.Position != br.BaseStream.Length)
                        {
                            Int64 sector_n = br.BaseStream.Position / SECTOR_SIZE;
                            byte[] tempBuffer = br.ReadBytes(SECTOR_SIZE);

                            bool dataArea = ( (sector_n >= dataranges[currentrange,0]) && (sector_n <= dataranges[currentrange,1])); // data area?

                            if (dataArea)
                            {
                                hash.TransformBlock(tempBuffer, 0, SECTOR_SIZE, null, 0);
                                bw.Write(tempBuffer);
                                
                                while (sector_n >= dataranges[currentrange,1]) //next range and skip nested ranges
                                {
                                    if (sector_n != 3820879) //last sector
                                    {
                                        currentrange ++;
                                    }
                                    else
                                    {
                                        break;
                                    }
                                    
                                }
                                
                                if (checkSecRange(sector_n, security_sectors))
                                {
                                    rs.BaseStream.Position = 0;
                                    for (int j = 0; j < SECTOR_SIZE; j += 2)
                                    {
                                        UInt16 sample = (UInt16)(Value(ref a_t, ref b_t, ref c_t) >> 8);
                                        rs.Write(sample);
                                    }
                                }
                            }
                            else
                            {
                                hash.TransformBlock(randomSector, 0, SECTOR_SIZE, null, 0);
                                bw.Write(randomSector);
                                
                                rs.BaseStream.Position = 0;
                                for (int j = 0; j < SECTOR_SIZE; j += 2)
                                {
                                    UInt16 sample = (UInt16)(Value(ref a_t, ref b_t, ref c_t) >> 8);
                                    rs.Write(sample);
                                }
                                
                            }
                        }
                    }
                    
                    else  // scrubbed && !seedflag
                    {
                        using (BinaryReader rc4i = new BinaryReader(new FileStream(rc4file, FileMode.Open)))
                        {
                            /*
                            randomSector = rc4i.ReadBytes(SECTOR_SIZE);
                            hash.TransformBlock(randomSector, 0, SECTOR_SIZE, null, 0);
                            
                            br.ReadBytes(SECTOR_SIZE);
                            bw.Write(randomSector);
                            */
                            randomSector = rc4i.ReadBytes(SECTOR_SIZE);
                            int currentrange = 0;
                            //while (br.BaseStream.Position < 0x1F400000)
                            while (br.BaseStream.Position != br.BaseStream.Length)
                            {
                                Int64 sector_n = br.BaseStream.Position / SECTOR_SIZE;
                                byte[] tempBuffer = br.ReadBytes(SECTOR_SIZE);

                                bool dataArea = ( (sector_n >= dataranges[currentrange,0]) && (sector_n <= dataranges[currentrange,1])); // data area?

                                if (dataArea)
                                {
                                    hash.TransformBlock(tempBuffer, 0, SECTOR_SIZE, null, 0);
                                    bw.Write(tempBuffer);
                                    
                                    while (sector_n >= dataranges[currentrange,1]) //next range and skip nested ranges
                                    {
                                        if (sector_n != 3820879) //last sector
                                        {
                                            currentrange ++;
                                        }
                                        else
                                        {
                                            break;
                                        }
                                        
                                    }
                                }
                                else
                                {
                                    hash.TransformBlock(randomSector, 0, SECTOR_SIZE, null, 0);
                                    bw.Write(randomSector);
                                    randomSector = rc4i.ReadBytes(SECTOR_SIZE);
                                }
                            }
                        }
                    }
                    hash.TransformFinalBlock(new byte[0], 0, 0);
                    string file_md5 = BitConverter.ToString(hash.Hash).Replace("-", "").ToLower();
                    Console.WriteLine("All done!");
                    if (rom_md5 == file_md5)
                    {
                        Console.WriteLine("md5 matched: {0}", file_md5);
                    }
                    else
                    {
                        Console.WriteLine("md5 mismatch!\nExpected:  " + rom_md5 + "\nCalculated:" + file_md5);
                    }
                }
                else // !scrubbed
                {
                    using (BinaryWriter rc4o = new BinaryWriter(new FileStream(rc4file, FileMode.OpenOrCreate)))
                    {
                        int currentrange = 0;
                        //int totaljunk = 0;
                        byte[] tempBuffer;
                        //while (br.BaseStream.Position < 0x1F400000)
                        while (br.BaseStream.Position != br.BaseStream.Length)
                        {
                            Int64 sector_n = br.BaseStream.Position / SECTOR_SIZE;
                            tempBuffer = br.ReadBytes(SECTOR_SIZE);

                            bool dataArea = ( (sector_n >= dataranges[currentrange,0]) && (sector_n <= dataranges[currentrange,1])); // data area?

                            if (dataArea)
                            {
                                bw.Write(tempBuffer);
                                
                                while (sector_n >= dataranges[currentrange,1]) //next range and skip nested ranges
                                {
                                    if (sector_n != 3820879) //last sector
                                    {
                                        currentrange ++;
                                        //Console.WriteLine("Total Junk: " + totaljunk.ToString());
                                    }
                                    else
                                    {
                                        break;
                                    }
                                    
                                }
                            }
                            else if (sector_n == firstjunksector)
                            {
                                if (seedflag)
                                {
                                    bw.Write(BitConverter.GetBytes(1));
                                    
                                }
                                else
                                {
                                    bw.Write(BitConverter.GetBytes(0));
                                }
                                bw.Write(BitConverter.GetBytes(seed));  // always 32bit
                                bw.Write(BitConverter.GetBytes(0));
                                bw.Write(BitConverter.GetBytes(0));
                                bw.Write(BitConverter.GetBytes(0));  // space for 128 bit rc4 key (3x32 bit)
                                bw.Write(StringToByteArray(rom_md5));
                                bw.Write(BitConverter.GetBytes(16)); // SS count
                                for (int k = 0; k < 16; k++)  // always 16 Security Secotrs
                                {
                                    bw.Write(BitConverter.GetBytes(security_sectors[k, 0]));
                                    bw.Write(BitConverter.GetBytes(security_sectors[k, 1]));
                                }
                                
                                while (bw.BaseStream.Position < (long)(firstjunksector + 1) * 0x800)
                                {
                                    bw.Write(Encoding.ASCII.GetBytes("JUNK"));
                                }
                                //totaljunk ++;
                                if (!seedflag)
                                {
                                    rc4o.Write(tempBuffer);
                                }
                            }
                            else if (sector_n < dataranges[currentrange,0])
                            {
                                bw.Write(junk);
                                //totaljunk ++;
                                if (!seedflag)
                                {
                                        rc4o.Write(tempBuffer);
                                }
                            }
                        }
                    //Console.WriteLine("Total Junk: " + totaljunk.ToString());   
                    }
                    if (seedflag && File.Exists(rc4file) && (new System.IO.FileInfo(rc4file).Length == 0))
                    {
                        File.Delete(rc4file);
                    }
                    
                    if (!seedflag)
                    {
                        long rc4head = (long)getPadSecCount(dataranges) * SECTOR_SIZE;
                        long rc4real = new System.IO.FileInfo(rc4file).Length;
                    
                        if (rc4head != rc4real)
                        {
                            Console.WriteLine("Error. Filesize Mismatch for rc4 file!\nExpected: " + (rc4head).ToString() + " Bytes\nActual:   " + (rc4real).ToString() + " Bytes");
                            Environment.Exit(0); 
                        }
                    }
                    
                    Console.WriteLine("All done!");
                }
            }
        }

    }

    private static bool checkSecRange(long sector_n, uint[,] security_sectors)
    {
        for (int i = 0; i < 16; i++)
        {
            if (security_sectors[i, 0] <= sector_n && sector_n <= security_sectors[i, 1]) return true;
        }

        return false;
    }

    private static byte[] newRandomSector(ref uint a_t, ref uint b_t, ref uint c_t)
    {
        throw new NotImplementedException();
    }

    private static uint[,] readSS(string ssRange)
    {
        uint[,] temp = new uint[16, 2];

        string[] ss = Regex.Split(ssRange, ",");

        for (int i = 0; i < 16; i++)
        {
            temp[i, 0] = Convert.ToUInt32(Regex.Split(ss[i], ":")[0]);
            temp[i, 1] = Convert.ToUInt32(Regex.Split(ss[i], ":")[1]);
        }

        return temp;
    }

    private static uint bruteForceSeed(string testFile)
    {
        BinaryReader br = new BinaryReader(new FileStream(testFile, FileMode.Open));
        br.BaseStream.Position = GP_OFFSET;
        byte[] sector = br.ReadBytes(SECTOR_SIZE);
        br.Close();

        var t1 = DateTime.Now;

        UInt32 seed = 0;

        Parallel.For(0x00000000, 0xffffffff, (i, state) =>
        {
            uint a_t = 0;
            uint b_t = 0;
            uint c_t = 0;

            Seed((uint)i, ref a_t, ref b_t, ref c_t);
            bool found = true;

            for (int j = 0; j < SECTOR_SIZE; j += 2)
            {
                UInt16 sampleGenerated = (UInt16)(Value(ref a_t, ref b_t, ref c_t) >> 8);
                byte low = (byte)(sampleGenerated & 0xff);
                byte high = (byte)((sampleGenerated >> 8) & 0xff);

                if ((sector[0 + j] != low) && (sector[1 + j] != high))
                {
                    found = false;
                    break;
                }
            }

            if (found)
            {
                seed = (UInt32)i;
                state.Stop();
            }
        });

        return seed;
    }

    private static void Seed(uint seed, ref uint a_t, ref uint b_t, ref uint c_t)
    {
        a_t = 0;
        b_t = b_seeds[seed & 7];
        c_t = seed;
        a_t = Value(ref a_t, ref b_t, ref c_t);
    }

    private static uint Value(ref uint a_t, ref uint b_t, ref uint c_t)
    {
        UInt64 result;
        result = c_t;
        result += 1;
        result *= b_t;
        result %= 0xFFFFFFFB;
        c_t = (UInt32)(result & 0xFFFFFFFF);
        return c_t ^ a_t;
    }
    private static bool mode(string fileName, byte[] junk, uint firstjunksector)
    {
        byte[] buffer = new byte[SECTOR_SIZE];
        using (BinaryReader br = new BinaryReader(new FileStream(fileName, FileMode.Open)))
        {
            br.BaseStream.Position = (long)firstjunksector * SECTOR_SIZE;
            buffer = br.ReadBytes(SECTOR_SIZE);
        }
        for (int i = 1024; i < SECTOR_SIZE; i++)
        {
            if (buffer[i] != junk[i]) return false;
        }
        return true;            
    }

    private static bool CompareArrays(byte[] buffer, byte[] randomSector)
    {
        for (int i = 0; i < SECTOR_SIZE; i++)
        {
            if (buffer[i] != randomSector[i]) return false;
        }
        return true;
    }

    private static byte[] JunkBlock()
    {
        byte[] junkBuffer = new byte[SECTOR_SIZE];

        byte[] junkChain = Encoding.ASCII.GetBytes("JUNK");

        for (int i = 0; i < 512; i++)
        {
            junkChain.CopyTo(junkBuffer, i * 4);
        }

        return junkBuffer;
    }


    private static Tuple<uint[,], string> getSS(string iso, MD5 hash)
    {
        List<uint> list = new List<uint>();
        uint[,] temp = new uint[16, 2];
        byte[] blank = new byte[SECTOR_SIZE]; // initial value is 0x00
        bool flag = false;
        uint start = 0;
        uint end = 0;
        uint ssrangecount = 0;
        uint sectorcount = 0;
        string file_md5 = "";
        using (BinaryReader br = new BinaryReader(new FileStream(iso, FileMode.Open)))
        {
            while (sectorcount < 0x30600)
            {
                byte[] isosector = br.ReadBytes(SECTOR_SIZE);
                hash.TransformBlock(isosector, 0, SECTOR_SIZE, null, 0);
                sectorcount ++;
            }
            while (sectorcount <= 0x376160) // first sector of game partition with zeropadded sectors at the end
            {
                byte[] isosector = br.ReadBytes(SECTOR_SIZE);
                hash.TransformBlock(isosector, 0, SECTOR_SIZE, null, 0);
                if (CompareArrays(blank, isosector) && !flag)
                {
                    start = sectorcount;
                    flag = true;
                }
                else if (!CompareArrays(blank, isosector) && flag)
                {
                    end = sectorcount - 1;
                    flag = false;
                    if (end - start == 0xFFF)
                    {
                        try
                        {
                        temp[ssrangecount, 0] = start;
                        temp[ssrangecount, 1] = end;
                        ssrangecount ++;
                        }
                        catch (IndexOutOfRangeException ex)
                        {
                            throw new ArgumentException("Index is out of range", ssrangecount.ToString(), ex);
                        }
                    }
                }
                sectorcount ++;
            }
            
            while (br.BaseStream.Position != br.BaseStream.Length)
            {
                byte[] isosector = br.ReadBytes(SECTOR_SIZE);
                hash.TransformBlock(isosector, 0, SECTOR_SIZE, null, 0);
            }
            
            hash.TransformFinalBlock(new byte[0], 0, 0);
            file_md5 = BitConverter.ToString(hash.Hash).Replace("-", "").ToLower();
            
            if (ssrangecount != 16)
            {
                Console.WriteLine("Aborting. Expected 16 Security Sector Ranges. Found: " + ssrangecount.ToString());
                Environment.Exit(0);
            }

        }
        return new Tuple<uint[,], string>(temp, file_md5);
    }
    
    private static void extractSearchTree(BinaryReader br, long dir_offset, uint dir_size, uint offset, long startoffset, List<uint> datasectors)
    {
        long this_offset = startoffset + dir_offset + offset * 4;
        if (debug)
        {
            Console.WriteLine("  this_offset: " + this_offset.ToString() + " startoffset " + startoffset.ToString() + " dir_offset " + dir_offset.ToString() + " offset*4 " + (offset * 4).ToString());
        }
        // integer division ceiling. ceil(i/j) = (i + j - 1) / j
        //Console.WriteLine( (this_offset/0x800).ToString() + " - " +  ((this_offset/0x800) + ((dir_size - (offset * 4) + 0x800 - 1)/0x800)).ToString());
        for (long i = this_offset/SECTOR_SIZE; i < (this_offset/SECTOR_SIZE) + ((dir_size - (offset * 4) + SECTOR_SIZE - 1)/SECTOR_SIZE); i++)
        {
            datasectors.Add((uint)i);
        }
        
        if ((offset * 4) >= dir_size)
        {
            return;
        }

        br.BaseStream.Position = this_offset;
        UInt16 left = br.ReadUInt16();
        UInt16 right = br.ReadUInt16();
        UInt32 sector = br.ReadUInt32();
        UInt32 size = br.ReadUInt32();
        Byte attrib = br.ReadByte();
        Byte name_length = br.ReadByte();

        long data_offset = (long)sector * SECTOR_SIZE;
        offset += 14;
        
        //read filename for debug
        byte[] filenameb = br.ReadBytes(name_length);
        string filename = System.Text.Encoding.ASCII.GetString(filenameb);
        /*
        if (filename == "Movies"){
            debug = true;
        }
        else if (filename == "ICEBERG.ark")
        {
            debug = false;
            Environment.Exit(0);
        }
        */
        if (debug)
        {
            Console.WriteLine("name " + filename + " left " + left.ToString() + " right " + right.ToString() + " sector " + sector.ToString() + " Size "+ size.ToString() + " attrib " + attrib.ToString() + " namelength " + name_length.ToString());
        }
        //Console.WriteLine(filename);
        
        if (left == 0xFFFF)
        {
            return;
        }

        // Handle left children
        if (left != 0)
        {
            extractSearchTree(br, dir_offset, dir_size, left, startoffset, datasectors);
        }

        if ((attrib & 0x10) != 0)  // 0x10 directory
        {
            if (size > 0)
            {
                if (debug)
                {
                    Console.WriteLine("  dir called");
                }
                extractSearchTree(br, data_offset, size, 0, startoffset, datasectors);
            }
        }

        else //file
        {
            //Console.WriteLine( ((startoffset + data_offset)/0x800).ToString() + " - " + ((startoffset + data_offset)/0x800 + ((size + 0x800 - 1) / 0x800)).ToString() );
            for (long i = (startoffset + data_offset)/SECTOR_SIZE; i < (startoffset + data_offset)/SECTOR_SIZE + ((size + SECTOR_SIZE - 1) / SECTOR_SIZE); i++)
            {
                datasectors.Add((uint)i);
            }
        }
        
        // Handle right children
        if (right != 0)
        {
            extractSearchTree(br, dir_offset, dir_size, right, startoffset, datasectors);
        }
    }
    
    private static void extractImage(BinaryReader br, uint startoffset, List<uint> datasectors)
    {
        uint headersec = (startoffset + 0x10000) / SECTOR_SIZE;
        datasectors.Add(headersec);
        datasectors.Add(headersec+1);
        br.BaseStream.Position = startoffset + 0x10000 + 20; // startoffset + XISO_HEADER_OFFSET + XISO_HEADER_DATA_LENGTH
        uint root_sector = br.ReadUInt32();
        uint root_size = br.ReadUInt32();
        long root_offset = (long)root_sector * SECTOR_SIZE;
        extractSearchTree(br, root_offset, root_size, 0, startoffset, datasectors);
    }
    
    private static uint[,] parseArray(List<uint> datasectors)
    {
        datasectors.Sort();
        List<uint> startlist = new List<uint>();
        List<uint> endlist = new List<uint>();
        uint start = datasectors[0];
        uint prev = datasectors[0] - 1;
        foreach (uint sector in datasectors)
        {
            if (prev == sector)
            {
                continue;
            }
            if ( (prev + 1) == sector)
            {
                prev = sector;
            }
            else
            {
                startlist.Add(start);
                endlist.Add(prev);
                start = sector;
                prev = sector;
            }
        }
        startlist.Add(start);
        endlist.Add(prev);
        // hacky part unknown padding at end probaly only OG XBOX
        
        uint zeropadbeginsector = 0x376160; // 0x1bb0b0000/0x800;
        uint lastsector = 0x3A4D4F; // (0x1D26A8000 / 0x800) -1;  last sector. Filesize / sectorsize -1
        startlist.Add(zeropadbeginsector);
        endlist.Add(lastsector);
        /*
        Console.WriteLine("TOTAL RANGES: " + startlist.Count.ToString() + " , " + endlist.Count.ToString());
        for (int i = 0; i < startlist.Count; i++)
        {
            Console.WriteLine(startlist[i].ToString() + " - " + endlist[i].ToString());
        }
        Console.WriteLine();
        */
        uint[,] secranges = new uint[startlist.Count, 2];
        for (int i = 0; i < startlist.Count; i++)
        {
            secranges[i,0] = startlist[i];
            secranges[i,1] = endlist[i];
        }
        return secranges;
    }
    
    private static uint[,] getDataArray(string file)
    {
        List<uint> datasectors = new List<uint>();
        using (BinaryReader br = new BinaryReader(new FileStream(file, FileMode.Open)))
        {
            extractImage(br, GP_OFFSET, datasectors);
        }
        return parseArray(datasectors);
    }
    
    private static byte[] StringToByteArray(string hex)
    {
        return Enumerable.Range(0, hex.Length)
                          .Where(x => x % 2 == 0)
                          .Select(x => Convert.ToByte(hex.Substring(x, 2), 16))
                          .ToArray();
    }
    
    
    private static uint[,] mergeArrays(uint[,] dtemp, uint[,] ss)
    {
        //bool ssend = false;
        uint[,] temp = new uint[dtemp.GetLength(0) + ss.GetLength(0), 2];
        //Console.WriteLine("dlen:" + dtemp.GetLength(0).ToString() + "  slen:" + ss.GetLength(0).ToString() + "  sum:" + (dtemp.GetLength(0) + ss.GetLength(0)).ToString());
        int countd = 0;
        int counts = 0;
        for (int i = 0; i < temp.GetLength(0) -1; i++)
        {
            //Console.WriteLine("i:" + i.ToString() + "  d:" + countd.ToString() + "  s:" + ((counts == 16) ? 15 : counts).ToString());
            if ( (dtemp[countd, 0] <= ss[((counts == 16) ? 15 : counts), 0]) || (counts == 16))
            {
                
                temp[i,0] = dtemp[countd,0];
                temp[i,1] = dtemp[countd,1];
                countd ++;
            }
            else
            {
                
                temp[i,0] = ss[counts,0];
                temp[i,1] = ss[counts,1];
                counts ++;


            }
        }
        // add last element
        //Console.WriteLine("  d:" + countd.ToString() + "  s:" + counts.ToString());
        //Console.WriteLine("counts==ss:" + (counts == ss.GetLength(0)).ToString() + "  countd==dtemp:" + (countd == dtemp.GetLength(0)).ToString());
        if (counts == ss.GetLength(0))
        {
            temp[temp.GetLength(0) - 1,0] = dtemp[countd,0];
            temp[temp.GetLength(0) - 1,1] = dtemp[countd,1];
        }
        else if (countd == dtemp.GetLength(0))
        {
            temp[temp.GetLength(0) - 1,0] = ss[counts,0];
            temp[temp.GetLength(0) - 1,1] = ss[counts,1];
        }
        return temp;
    }
    

    private static uint getPadSecCount(uint[,] dataranges)
    {
        uint datsecs = 0;
        uint high = 0;
        for (int i = 0; i < dataranges.GetLength(0); i++)
        {
            if (dataranges[i,1] > high)  // not nested
            {
                if (dataranges[i,0] >= high) //not intersecting
                {
                    datsecs = datsecs + (dataranges[i,1] - dataranges[i,0] + 1);
                }
                else //intersecting (unknown if case exists)
                {
                    datsecs = datsecs + (dataranges[i,1] - high);
                    Console.WriteLine("Warning: Intersecting ranges");
                }
                high = dataranges[i,1];
            }
        }
        return (0x3A4D50 - 0x30600 - datsecs);  //total sectors of redump image - sectors of videopartition - datsecs
    }        
    
    private static uint getfirstjunksector(uint[,] dataranges)
    {
        //Console.WriteLine("Datarange00 " + dataranges[0,0].ToString());
        if (dataranges[0,0] != 198144) //first sector of game partition is no data sector
        {
            return 198144;
        }
        else
        {
            for (int i = 0; i < dataranges.GetLength(0); i++)
            {
                if ((dataranges[i+1,0] - dataranges[i,1]) > 1) //
                {
                    return dataranges[i,1] + 1;
                }
            }
        }
        Console.WriteLine("Error: No first Junksector found!");
        Environment.Exit(0);
        return 0;
    }
    
    private static int getVersion(string fileName)
    {
        
        if (new System.IO.FileInfo(fileName).Length != 0x1D26A8000)
        {
            return 0;
        }
        
        byte[] MAGIC = Encoding.ASCII.GetBytes("XBOX_DVD_LAYOUT_TOOL_SIG");
        using (BinaryReader br = new BinaryReader(new FileStream(fileName, FileMode.Open)))
        {
            br.BaseStream.Position = 0x18310800;
            if (!(MAGIC.SequenceEqual(br.ReadBytes(24))))
            {
                return 0;
            }
            br.ReadBytes(8);
            bool wave4 = (br.ReadBytes(8).SequenceEqual(new byte[8]));
            if (wave4)
            {
                br.BaseStream.Position = (0x18310834);
                return (int)br.ReadUInt16();
            }
            else
            {
                br.BaseStream.Position = (0x18310824);
                return (int)br.ReadUInt16();
            }
            
        }
    }
    
    private static void test(string file)
    {
        uint[,] dr = getDataArray(file);
    }
}
