using System;
using System.IO;
using System.Collections.Generic;
using System.Linq;

namespace IDS
{
    class Program
    {
        // Help message to mitigate errors
        private const string HelpMessage =  "Argument Format: dotnet run {optflag} {file path} {optflag2}\n" +
                                            "\nOptflags:      -m       :   Misuse classification mode\n" +
                                            "                 -a       :   Anomaly classification mode\n" +
                                            "                 -h       :   Display this help message again\n" +
                                            "\nOptflags 2:    -s       :   Surpresses output\n" +
                                            "               {out file} :   Redirects output to a file\n" +
                                            "\nRunning program without flags will run both classifiers on file.";

        // Error messages for when input format doesn't match desired structure
        private const string InvalidFlagError = "ERROR: Invalid flag provided.";
        private const string InvalidFileError = "ERROR: Invalid file path provided.";
        private const string InvalidArgsError = "ERROR: Invalid number of arguments provided.";
        
        // Int for deciding which IDS mode to use (0 = misuse, 1 = anomaly, 2 = both), String for reading from input file
        private static int mode;
        private static List<string> paths = new List<string>();

        // Int for deciding which output method to use (0 = console, 1 = surpress, 2 = file), String for if outputting to a file
        private static int outMode;
        private static string outPath;

        static void Main(string[] args)
        {
					switch( args.Length ){
						case 0:
							Console.Write("Specify mode of operation [ (A)nomaly, (M)isuse, (B)oth ]: ");
							string answer = Console.ReadLine();
							opFlagParser(answer);
							Console.Write("Specify file: ");
							answer = Console.ReadLine();
							fileParser(answer);
							break;
						case 1:
							opFlagParser(args[0]);
							break;
						case 2:
							opFlagParser(args[0]);
							fileParser(args[1]);
							break;
						case 3:
							opFlagParser(args[0]);
							fileParser(args[1]);
							destParser(args[2]);
							break;
						default:
							return;
					}

					if( mode == 0 || !paths.Any() ){
						Console.WriteLine("Program Aborted");
						return;
					}


            // Construct the two classifiers for later
            MisuseClassifier Misuse = new MisuseClassifier();
            AnomalyClassifier Anomaly = new AnomalyClassifier();

            // List of packets being read in from the file to be used for classification
            List<Packet> packets = Generator();

            // Opens a StreamReader to parse the packets out of the file line-by-line, storing them in the packets list
            //using (StreamReader file = new StreamReader(path))
            //{
                //string ln;
                //List<string> lines = new List<string>();

                //while((ln = file.ReadLine()) != null){
                    //packets.Add(new Packet(ln));
                //}
                //file.Close();
            //}

            if (mode == 1) // If mode is 1, do misuse classification and print the findings
            {
                Misuse.classify(packets);
                printAllPackets(packets);
                Console.WriteLine(Misuse.ToString());
            } 
            else if (mode == 2) // If mode is 2, do anomaly classification and print the findings
            {
                Anomaly.classify(packets);
                printAllPackets(packets);
                Console.WriteLine(Anomaly.ToString());
            } 
            else // Else, do both and print the findings
            {
                Misuse.classify(packets);
                printAllPackets(packets);
                Console.WriteLine(Misuse.ToString());

                Console.WriteLine();

                Anomaly.classify(packets);
                printAllPackets(packets);
                Console.WriteLine(Anomaly.ToString());
            }
        }

        /*
         * Function:    printAllPackets
         * 
         * Input:       List of packets to print
         * 
         * Description: Takes a list of packets and calls ToString() for each individual item. If outMode is set
         *              to 0, prints them to console. If outMode is set to 2, prints them to destination file. Otherwise,
         *              does nothing.
         */
        private static void printAllPackets(List<Packet> packs)
        {
            if(outMode == 1) // If outMode is 1, write packet information to Console
            {
                foreach(Packet pack in packs)
                {
                    Console.WriteLine(pack.ToString());
                }
            } else if (outMode == 2) // If outMode is 2, write packet information to file. Else, do nothing
            {
                using (StreamWriter wr = new StreamWriter(outPath))
                {
                    foreach (Packet pack in packs)
                    {
                        wr.WriteLine(pack.ToString());
                    }
                }
            }
        }

        /*
         * Function:    opFlagParser
         * 
         * Inputs:      String to be checked for matching flag, file to be used as input
         * 
         * Output:      Boolean determining if the operation was successful
         * 
         * Description: Takes in two arguments that may be a flag and a file path. Checks to make sure 
         *              the first argument is a known flag before verifying the second argument is an existing file.
         */
        private static void opFlagParser(string preFlag)
        {
					string flag = preFlag.ToLower();
					switch (flag) // Switch through possible values of flags to decide what classification to do
					{
						case "-m": // If flag is -m, do misuse detection
						case "m":
						case "misuse":
								mode = 1;
								break;
						case "-a": // If flag is -a, do anomaly detection
						case "a":
						case "anomaly":
								mode = 2;
								break;
						case "-h": // If flag is -h, print help message and exit
						case "h":
						case "help":
								Console.WriteLine(HelpMessage);
								break;
						default: // Otherwise, invalid flag. Exit program
								Console.WriteLine(InvalidFlagError);
								Console.WriteLine(HelpMessage);
								break;
					}
        }

				private static void fileParser(string path_name){
					if( Directory.Exists(path_name) )
					{
						paths.AddRange( Directory.GetFiles(path_name) );
					}
					else if( File.Exists(path_name) )
					{
						paths.Add(path_name);
					} 
					else
					{
							Console.WriteLine(InvalidFileError);
							Console.WriteLine(HelpMessage);
					}
				}

        private static void destParser(string opt)
        {
            if(opt == "-s") // If opt is -s, surpress output
            {
                outMode = 1;
            }
            else if (File.Exists(opt)) // Else, check if it's a file
            {
                outMode = 2;
                outPath = opt;
            }
            else // If neither, print error message and exit program
            {
                Console.WriteLine(InvalidFlagError);
                Console.WriteLine(HelpMessage);
            }
        }

        private static List<Packet> Generator()
        {
					/* Prepares variables needed to split the path string */
					char[] splitters = { '/', '.' };
					List<string> parts = new List<string>();

					/* Initializes a new list to hold the packets */
					List<Packet> created_packets = new List<Packet>();

					/* For each file provided through input, find what type of attack it is and pass on to Packet creator */
					foreach( string path in paths )
					{
						parts.AddRange( path.Split(splitters) );
						CreatePackets(created_packets, path, parts[parts.Count() - 2]);
					}

					/* Return the final list of packets */
					return created_packets;
        }

        static void CreatePackets(List<Packet> packet_storage, string packet_stream, string type)
        {

					try
					{
						/* Opens a StreamReader on the provided file */
						using( StreamReader packet_reader = new StreamReader(packet_stream))
						{
							/* While there are lines left to read in the file, process them as new packets */
							string packet_string;
							while( (packet_string = packet_reader.ReadLine()) != null )
							{
									packet_storage.Add(new Packet(packet_string, type));
							}
							packet_reader.Close();
						}
					}
					catch(FileNotFoundException e)
					{
						Console.WriteLine(e.Message);
					}
    		}
		}
}