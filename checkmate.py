import random
from math import log2
from chess import pgn, Board

def no_to_bin_str(num: int, bits: int):
    # Convert the number to a binary string and remove the '0b' prefix
    binary = bin(num)[2:]

    # Pad the binary string with leading zeros to ensure it's 'bits' long
    return binary.zfill(bits)

def random_user_id():
    return f"{random.randint(100000, 999999)}"

def random_metadata():
    events = [
        "Friendly Match", "Tournament", "Casual Game", "Championship", 
        "Club Championship", "Simultaneous Exhibition", "Charity Match", 
        "Blitz Tournament", "Rapid Championship", "Online Invitational"
    ]
    locations = [
        "Local Club", "Online", "City Park", "University Hall", "Community Center", 
        "Chess Cafe", "Mountain Retreat", "Coastal Town", "National Stadium", 
        "Historical Landmark"
    ]
    expected_openings = [
        "Sicilian Defense", "French Defense", "Caro-Kann", "Ruy Lopez", "Italian Game", 
        "English Opening", "King's Indian Defense", "Queen's Gambit", 
        "Nimzo-Indian Defense", "Pirc Defense", "Grünfeld Defense"
    ]
    
    # Generate the first player's rating
    white_elo = random.randint(200, 3000)
    # Calculate the range for the second player's rating
    lower_bound = int(white_elo * 0.9)
    upper_bound = int(white_elo * 1.1)
    
    # Generate the second player's rating within the specified range
    black_elo = random.randint(lower_bound, upper_bound)
    
    results = ["1-0", "0-1", "1/2-1/2", "*"]  # Possible outcomes

    metadata = {
        "Event": random.choice(events),
        "Site": random.choice(locations),
        "Date": f"{random.randint(1990, 2023)}.{random.randint(1, 12):02d}.{random.randint(1, 31):02d}",
        "Round": str(random.randint(1, 15)),
        "White": random_user_id(),  # Random user ID for White player
        "Black": random_user_id(),  # Random user ID for Black player
        "ExpectedOpening": random.choice(expected_openings),
        "WhiteElo": str(white_elo),
        "BlackElo": str(black_elo),
        "Result": random.choice(results),
        "Annotator": random_user_id(),  # Random ID for annotator
        "Variation": random.choice(["Main Line", "Alternative Line", "Quiet Move", "Aggressive Line", "Theoretical Novelty"]),
        "EventDate": f"{random.randint(1990, 2023)}.{random.randint(1, 12):02d}.{random.randint(1, 31):02d}",
        "TimeControl": random.choice(["3+2", "5+0", "10+0", "15+10", "30+0", "60+0", "90+30"])
    }

    # Randomly select a number of keys to hide
    keys_to_hide = random.sample(list(metadata.keys()), random.randint(1, len(metadata) // 2))
    
    # Set the selected keys' values to "Hidden"
    for key in keys_to_hide:
        metadata[key] = "Hidden"

    return metadata

def make_gambit(sample_file: str):
    bittify = (255).bit_length()  # Determine the number of bits required to represent the maximum byte value (255)

    with open(sample_file, "rb") as f:  # Open the file in binary read mode
        file01 = list(f.read())  # Read the file contents and convert it into a list of bytes

    bits = bittify * len(file01)  # Calculate the total number of bits from the number of bytes in the file
    print(f"bits in the file: {bits}")
    pgnlist = []  # Initialize an empty list to store PGN (Portable Game Notation) outputs
    current_pos = 0  # Initialize a bit index to track the current position in the file bits
    board_instance = Board()  # Create a new chess board instance to simulate the game

    k = 0

    while True:  # Start an infinite loop for generating moves until a termination condition is met
        k+=1
        gen_moves = board_instance.generate_legal_moves()  # Generate legal moves for the current position on the chess board

        moves_list = list(board_instance.generate_legal_moves())

        # Calculate the log2 length separately and convert it to an integer.
        log_length = int(log2(len(moves_list)))

        # Calculate the number of bits remaining.
        remaining_bits = bits - current_pos

        # Take the minimum of the two calculated values.
        # ensure bits_req is not larger than either the required bits to represent the indices or the bits left to read. This prevents indexing errors or reading past the end of available bits.
        bits_req = min(log_length, remaining_bits)

        bits_map_set_of_moves = {}  # Initialize a dictionary to map move UCI (Universal Chess Interface) strings to their binary representation
        
        # Create a dictionary of valid moves, mapping UCI strings to their corresponding binary strings
        valid_moves = {
            anti_illegal_move.uci(): no_to_bin_str(i, bits_req)
            for i, anti_illegal_move in enumerate(gen_moves)
            if len(no_to_bin_str(i, bits_req)) <= bits_req
        }

        bits_map_set_of_moves.update(valid_moves)  # Update the move_bits dictionary with valid moves
        
        next_byte_i = current_pos // bittify  # Calculate the index of the closest byte in the file that corresponds to the current bit index
        strs = ''  # Initialize a string to accumulate binary strings from the file bytes

        # Extract up to two bytes from the file and convert them to binary strings
        for byte1 in file01[next_byte_i:next_byte_i + 2]:
            binary_string = no_to_bin_str(byte1, bittify)  # Convert the byte to a binary string
            strs += binary_string  # Accumulate the binary string

        start_index = current_pos % bittify  # Calculate the starting index for extracting bits from the file chunk pool
        next_str = ''  # Initialize a string to store the next chunk of bits to be compared with legal move binaries

        # Extract the relevant bits from the file chunk pool based on the maximum binary length
        for i in range(bits_req):
            if start_index + i < len(strs):  # Ensure we don't go out of bounds
                next_str += strs[start_index + i]  # Append the bit to the next chunk

        current_pos += bits_req  # Increment the file bit index by the maximum binary length of the legal moves

        # Iterate over the valid moves to find a match with the extracted file bits
        for movei in bits_map_set_of_moves:
            bits_mapped = bits_map_set_of_moves[movei]  # Get the binary representation of the move
            if bits_mapped == next_str:  # Check if it matches the next file chunk
                board_instance.push_uci(movei)  # Push the move onto the chess board
                break  # Exit the loop once a move is found
        
        # Define a list of conditions that can terminate the loop and trigger PGN generation
        conditions = [
            sum(1 for _ in gen_moves) <= 1,  # Only one or no legal moves left
            current_pos >= bits,  # End of file reached
        ]

        if any(conditions):  # If any of the conditions are true, generate the PGN output
            pgn_ = pgn.Game()  # Create a new PGN game object
            metadata = random_metadata()  # Generate random metadata for the game
            
            # Add metadata headers to the PGN game
            for key, value in metadata.items():
                pgn_.headers[key] = value

            pgn_.add_line(board_instance.move_stack)  # Add the move stack from the chess board to the PGN
            pgnlist.append(str(pgn_))  # Convert the PGN game to a string and append it to the output list
            board_instance.reset()  # Reset the chess board for the next game simulation

        if current_pos >= bits:  # Break the loop if the end of the file has been reached
            break

    print(f"k: {k}\n\n")
    return "\n\n".join(pgnlist)  # Return all collected PGN strings joined by two newline characters