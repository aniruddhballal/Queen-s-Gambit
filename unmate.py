from math import log2  # Import the log2 function to calculate binary logarithms (base 2)
from chess import Board, pgn  # Import the Board class from the chess module to handle chess board operations
from io import StringIO

def listify_pgns(pgn_string: str):  
    # Initialize an empty list to store parsed pgn.Game objects
    games = []
    
    # Create an in-memory file-like object from the PGN string
    pgn_stream = StringIO(pgn_string)

    # Read the first chess game from the PGN string
    game = pgn.read_game(pgn_stream)
    
    # Loop through the PGN stream and read each game until no more games are left
    while game:  # While there is a valid game (not None)
        games.append(game)  # Add the current game to the list
        game = pgn.read_game(pgn_stream)  # Read the next game from the stream
    
    # Return the list of all parsed games
    return games

def undo_gambit(games_pgn: str, output_og_sample_file: str):
    moves_processed = 0  # Initialize a counter to keep track of the total number of moves processed
    bittify = (255).bit_length()  # Set the bit length for 1 byte, which is 8 (since 255 is 11111111 in binary)
    
    # Load games from PGN string
    # Convert the PGN string into a list of chess games (using a helper function)
    pgn_list = listify_pgns(games_pgn)

    # Ensure that the result is in a list form
    iterable_games = list(pgn_list)  # Convert the iterable of games into a list to iterate over later

    # Prepare to write to the output file in binary mode
    op_dec_file = open(output_og_sample_file, "wb")
    try:
        dec_data = ""  # Initialize a string to store the binary representation of moves
        # Loop through each game in the PGN list
        for pgn_g_num, g in enumerate(iterable_games):
            board_instance = Board()  # Initialize a new chess board for each game
            moves_list = list(g.mainline_moves())  # Get the main line of moves for the current game as a list
            moves_processed += len(moves_list)  # Update the total move count

            # Loop through each move in the game
            for move_i, iterable_moves in enumerate(moves_list):
                # Get UCIs (Universal Chess Interface) of legal moves in the current position
                moves_possible = board_instance.generate_legal_moves()  # Get a generator of all legal moves
                strs = [move_iterable.uci() for move_iterable in moves_possible]  # Convert legal moves into UCI string format

                # Get binary representation of the move played
                indexify_move = strs.index(iterable_moves.uci())  # Find the index of the move in the list of legal moves

                # Convert the index to a binary string and remove the '0b' prefix
                pad_indexed_bin = bin(indexify_move)[2:]  # Convert index to a binary string without the '0b' prefix

                # Determine maximum binary length for the current move
                # Check if we are at the last game and last move
                game_over = (pgn_g_num == len(iterable_games) - 1)  # Check if this is the last game
                last_move = (move_i == len(moves_list) - 1)  # Check if this is the last move in the game

                if game_over and last_move:
                    # If last game and move, calculate max binary length but adjust for file byte size
                    moves_count = len(strs)  # Get the number of legal moves
                    log_length = int(log2(moves_count))
                    remaining_bits = bittify - (len(dec_data) % bittify)
                    bits_req = min(log_length, remaining_bits)  # refer to checkmate-make_gambit to understand whats happening here

                else:
                    # For all other moves, calculate max binary length normally
                    moves_count = len(strs)  # Get the number of legal moves
                    bits_req = int(log2(moves_count))  # Calculate max binary length based on legal moves

                # Pad the binary string of the move to ensure correct length
                test_pad = bits_req - len(pad_indexed_bin)  # Calculate required padding
                non_neg_padding = max(0, test_pad)  # Ensure padding is non-negative
                padding = "0" * non_neg_padding  # Create a padding string of zeros
                pad_indexed_bin = padding + pad_indexed_bin  # Prepend the padding to the binary string

                # Play the move on the chess board
                next_move = iterable_moves.uci()  # Get the UCI representation of the move
                board_instance.push_uci(next_move)  # Push the move to update the chess board

                # Add the move's binary representation to the output data string
                dec_data += pad_indexed_bin  # Append the binary string of the move to output data

                # Check if the output_data length is a multiple of 8 bits (a full byte)
                if len(dec_data) % bittify == 0:
                    byte_values = []  # Initialize a list to store byte values

                    # Loop through the output_data in 8-bit chunks
                    num_chunks = len(dec_data) / bittify  # Calculate number of 8-bit chunks in output data
                    i = 0  # Initialize the chunk index counter

                    # Process each chunk of 8 bits
                    while i < int(num_chunks):
                        start_index = i * bittify  # Calculate the start index for the chunk
                        end_index = start_index + bittify  # Calculate the end index for the chunk

                        chunk = ''  # Initialize an empty string for the chunk
                        for indexify_move in range(start_index, end_index):
                            chunk += dec_data[indexify_move]  # Append each bit from the chunk to the chunk string

                        # Convert the 8-bit chunk into an integer
                        byte_value = 0  # Initialize the byte value
                        for bit in chunk:
                            byte_value = byte_value * 2 + int(bit)  # Shift bits left and add the current bit

                        byte_values.append(byte_value)  # Append the byte value to the list
                        i += 1  # Increment the chunk index counter

                    # Write the byte values to the output file
                    for byte_value in byte_values:
                        byte = byte_value.to_bytes(1, byteorder='big')  # Convert each byte value to a byte
                        op_dec_file.write(byte)  # Write the byte to the output file

                    dec_data = ""  # Reset the output_data string for the next iteration
    finally:
        op_dec_file.close()