using System.Linq;

namespace IDS
{
	internal static class Program
	{
		// Help message to mitigate errors
		private const string HelpMessage = "Argument Format: dotnet run {optflag} {file path} {optflag2}\n" +
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
		private static int _mode;
		private static readonly List<string?> Paths = new();

		// Int for deciding which output method to use (0 = console, 1 = suppress, 2 = file), String for if outputting to a file
		private static int _outMode;
		private static string? _outPath;

		public static void Main(string?[] args)
		{
			switch (args.Length)
			{
				case 0:
					Console.Write("Specify mode of operation [ (A)nomaly, (M)isuse, (B)oth ]: ");
					string? answer = Console.ReadLine();
					OpFlagParser(answer);
					Console.Write("Specify input file or directory: ");
					answer = Console.ReadLine();
					FileParser(answer);
					Console.Write("Specify output method [ (S)uppress, (D)isplay, (F)ile ]: ");
					answer = Console.ReadLine();
					DestParser(answer);
					break;
				case 1:
					OpFlagParser(args[0]);
					_outMode = 0;
					break;
				case 2:
					OpFlagParser(args[0]);
					FileParser(args[1]);
					_outMode = 0;
					break;
				case 3:
					OpFlagParser(args[0]);
					FileParser(args[1]);
					DestParser(args[2]);
					break;
				default:
					Console.WriteLine(InvalidArgsError);
					Console.WriteLine(HelpMessage);
					return;
			}

			if (_mode == 0 || !Paths.Any())
			{
				Console.WriteLine("Program Aborted");
				return;
			}


			// Construct the two classifiers for later
			List<IClassifier> packetClassifier = new();

			switch (_mode)
			{
				// If mode is 1, do misuse classification
				case 1:
					packetClassifier.Add(new MisuseClassifier());
					break;
				// If mode is 2, do anomaly classification
				case 2:
					packetClassifier.Add(new AnomalyClassifier());
					break;
				// Else, do both
				default:
					packetClassifier.Add(new MisuseClassifier());
					packetClassifier.Add(new AnomalyClassifier());
					break;
			}

			if (!Paths.Any())
			{
				foreach (var classifier in packetClassifier)
				{
					ClassifyFromStream(classifier);
				}
			}
			else
			{
				foreach (var classifier in packetClassifier)
				{
					OutputData(classifier, ClassifyFromFile(classifier));
				}
			}

			Console.WriteLine("Press any key to close...");
			Console.ReadKey();
		}

		private static List<Packet> ClassifyFromFile(IClassifier classifier)
		{
			List<Packet> packets = new();

			foreach (var path in Paths)
			{
				try
				{
					/* Opens a StreamReader on the provided file */
					Debug.Assert(path != null, nameof(path) + " != null");
					using StreamReader packetReader = new(path);
					
					string? packetString;
					
					/* While there are lines left to read in the file, process them as new packets */
					while ((packetString = packetReader.ReadLine()) != null)
					{
						packets.Add(new Packet(packetString));
					}

					packetReader.Close();
				}
				catch (FileNotFoundException e)
				{
					Console.WriteLine(e.Message);
				}
			}
			
			classifier.ClassifyAll(packets);
			return packets;
		}

		private static void ClassifyFromStream(IClassifier classifier)
		{
			//TO-DO: Implement reading packets from Network
			string? packetString;
			while ( ( packetString = Console.ReadLine() ) != null)
			{
				try
				{
					classifier.Classify(new Packet(packetString));
				}
				catch
				{
					Console.WriteLine("Invalid packet format.");
					return;
				}
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
		private static void OutputData(IClassifier classifier, List<Packet> packs)
		{
			switch (_outMode)
			{
				// If outMode is 0, write packet and classifier information to Console
				case 0:
				{
					foreach (Packet pack in packs)
					{
						Console.WriteLine(pack.ToString());
					}
					
					Console.WriteLine( classifier.ToString() );

					break;
				}
				// If outMode is 1, suppress packet output and only print classifier report
				case 1:
				{
					Console.WriteLine( classifier.ToString() );
					
					break;
				}
				// If outMode is 2, write packet information to file and classifier report to console. Else, do nothing
				case 2:
				{
					if (_outPath != null)
					{
						using StreamWriter wr = new(_outPath);
				
						foreach (Packet pack in packs)
						{
							wr.WriteLine(pack.ToString());
						}
					
						wr.Close();
					}

					Console.WriteLine(classifier.ToString());
					Console.WriteLine("Log written to: " + _outPath);

					break;
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
		private static void OpFlagParser(string? preFlag)
		{
			Debug.Assert(preFlag != null, nameof(preFlag) + " != null");
			string flag = preFlag.ToLower();
			switch (flag) // Switch through possible values of flags to decide what classification to do
			{
				case "-m": // If flag is -m, do misuse detection
				case "m":
				case "misuse":
					_mode = 1;
					break;
				case "-a": // If flag is -a, do anomaly detection
				case "a":
				case "anomaly":
					_mode = 2;
					break;
				case "-b": // If flag is -b, do both
				case "b":
				case "both":
					_mode = 3;
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

		private static void FileParser(string? pathName)
		{
			if (Directory.Exists(pathName))
			{
				Paths.AddRange(Directory.GetFiles(pathName));
			}
			else if (File.Exists(pathName))
			{
				Paths.Add(pathName);
			}
			else
			{
				Console.WriteLine(InvalidFileError);
				Console.WriteLine(HelpMessage);
			}
		}

		private static void DestParser(string? opt)
		{

			if (opt?.ToLower() is "-d" or "d" or "display")
			{
				_outMode = 0;
			}
			else if (opt?.ToLower() is "-s" or "s" or "suppress") // If opt is matches suppress flag, suppress output
			{
				_outMode = 1;
			}
			else if (opt?.ToLower() is "-f" or "f" or "file")
			{
				try
				{
					string dir = Path.Combine(Directory.GetCurrentDirectory(), "Reports");
					if (!Directory.Exists(dir))
					{
						Directory.CreateDirectory(dir);
					}

					DateTime today =  DateTime.Today;
					
					string outputFile = Path.Combine(dir, today.ToString("MM-dd-yyyy") + ".txt");

					if (!File.Exists(outputFile))
					{
						File.Create(outputFile);
					}

					_outMode = 2;
					_outPath = outputFile;
				}
				catch
				{
					_outMode = 0;
				}
			}
		}
	}
}