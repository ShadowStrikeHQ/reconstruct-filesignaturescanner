#!/usr/bin/env python3

import argparse
import logging
import os
import sys
import magic  # python-magic
import olefile  # olefile
import json
from typing import Dict, List, Optional

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


class FileSignatureScanner:
    """
    Scans a file and identifies the file type based on its signature.
    """

    def __init__(self, signature_db: Optional[str] = None):
        """
        Initializes the FileSignatureScanner.

        Args:
            signature_db (str, optional): Path to a custom signature database file (JSON).
                                          If None, uses python-magic for signature detection.
        """
        self.signature_db = signature_db
        self.signatures: Dict[str, List[str]] = {}  # type: ignore
        self.magic = magic.Magic(mime=True, uncompress=True)  # Initialize magic object for mime type detection

        if self.signature_db:
            try:
                with open(self.signature_db, 'r') as f:
                    self.signatures = json.load(f)
                logging.info(f"Loaded signature database from: {self.signature_db}")
            except FileNotFoundError:
                logging.error(f"Signature database not found: {self.signature_db}")
                raise FileNotFoundError(f"Signature database not found: {self.signature_db}")
            except json.JSONDecodeError as e:
                logging.error(f"Error decoding JSON from {self.signature_db}: {e}")
                raise ValueError(f"Invalid JSON in signature database: {e}")

    def identify_file_type(self, file_path: str) -> Optional[str]:
        """
        Identifies the file type based on its signature.

        Args:
            file_path (str): The path to the file to scan.

        Returns:
            str: The identified file type, or None if not found.
        """

        if not os.path.exists(file_path):
            logging.error(f"File not found: {file_path}")
            return None

        try:
            with open(file_path, 'rb') as f:
                header = f.read(1024)  # Read a portion of the file for signature analysis
        except IOError as e:
            logging.error(f"Error reading file: {file_path} - {e}")
            return None

        if self.signature_db:
            # Custom signature database logic
            for file_type, signatures in self.signatures.items():
                for signature in signatures:
                    if header.startswith(bytes.fromhex(signature)):
                        logging.info(f"Identified file type as: {file_type} (based on signature database)")
                        return file_type
        else:
            # Use python-magic for identification
            try:
                mime_type = self.magic.from_buffer(header)
                if mime_type:
                    logging.info(f"Identified file type as: {mime_type} (using python-magic)")
                    return mime_type
                else:
                     logging.warning(f"Could not determine file type for {file_path} using python-magic.")
                     return None
            except Exception as e:
                logging.error(f"Error using python-magic: {e}")
                return None

        logging.warning(f"File type not identified for: {file_path}")
        return None

    def extract_data(self, file_path: str, file_type: str) -> Optional[bytes]:
        """
        Extracts data from the file based on the identified file type.  This is a placeholder
        and can be extended based on specific file type requirements.

        Args:
            file_path (str): The path to the file.
            file_type (str): The identified file type.

        Returns:
            bytes: Extracted data (or None if extraction fails).
        """

        if file_type == "application/x-ole-storage":  # Example: Handle OLE files (e.g., older MS Office)
            try:
                if olefile.isOleFile(file_path):
                    ole = olefile.OleFileIO(file_path)
                    # Example: Extract the first stream's data
                    for stream_name in ole.listdir():
                        if stream_name:
                            stream_data = ole.openstream(stream_name[0]).read()
                            logging.info(f"Extracted data from stream: {stream_name[0]}")
                            return stream_data  # Return the first stream for simplicity
                    ole.close()
                    logging.warning("No streams found in OLE file.")
                    return None
                else:
                    logging.error(f"{file_path} is not a valid OLE file.")
                    return None

            except olefile.OleFileIOError as e:
                logging.error(f"Error processing OLE file: {e}")
                return None

        elif file_type == "image/jpeg":
            # Example: Attempt to extract the entire JPEG content
            try:
                with open(file_path, 'rb') as f:
                    data = f.read()
                logging.info(f"Extracted all data as JPEG content.")
                return data
            except IOError as e:
                logging.error(f"Error reading JPEG file: {e}")
                return None

        else:
            logging.warning(f"No extraction method defined for file type: {file_type}")
            return None


def setup_argparse() -> argparse.ArgumentParser:
    """
    Sets up the argument parser.

    Returns:
        argparse.ArgumentParser: The argument parser.
    """
    parser = argparse.ArgumentParser(description="Scans a file and identifies its type based on signature.")
    parser.add_argument("file_path", help="Path to the file to scan.")
    parser.add_argument("-d", "--database", help="Path to a custom signature database (JSON).", required=False)
    parser.add_argument("-e", "--extract", action="store_true", help="Attempt data extraction based on identified file type.", required=False)
    parser.add_argument("-o", "--output", help="Path to save extracted data.", required=False)
    return parser


def main():
    """
    Main function.
    """
    parser = setup_argparse()
    args = parser.parse_args()

    try:
        scanner = FileSignatureScanner(signature_db=args.database)
        file_type = scanner.identify_file_type(args.file_path)

        if file_type:
            print(f"Identified file type: {file_type}")

            if args.extract:
                extracted_data = scanner.extract_data(args.file_path, file_type)
                if extracted_data:
                    if args.output:
                        try:
                            with open(args.output, "wb") as outfile:
                                outfile.write(extracted_data)
                            logging.info(f"Extracted data saved to: {args.output}")
                            print(f"Extracted data saved to: {args.output}")

                        except IOError as e:
                            logging.error(f"Error writing extracted data to file: {e}")
                            print(f"Error writing extracted data to file: {e}")

                    else:
                         # Output data to stdout as a last resort.  WARNING: This could be binary data.
                        logging.warning("No output path specified.  Outputting extracted data to stdout (potentially dangerous).")
                        sys.stdout.buffer.write(extracted_data)
                else:
                    print("No data extracted.")

        else:
            print("File type not identified.")

    except FileNotFoundError as e:
        print(f"Error: {e}")
        sys.exit(1)
    except ValueError as e:
        print(f"Error: {e}")
        sys.exit(1)
    except Exception as e:
        logging.exception("An unexpected error occurred:")
        print(f"An unexpected error occurred: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()