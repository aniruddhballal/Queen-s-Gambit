import random
from math import log2
from chess import pgn, Board
from util import to_binary_string

def random_user_id():
    return f"{random.randint(1000000, 9999999)}"

def random_metadata():
    events = ["Friendly Match", "Tournament", "Casual Game", "Championship"]
    locations = ["Local Club", "Online", "City Park", "University Hall", "Community Center"]
    openings = ["Sicilian Defense", "French Defense", "Caro-Kann", "Ruy Lopez", "Italian Game"]
    ratings = [random.randint(1200, 2800) for _ in range(2)]  # Random ratings for two players
    results = ["1-0", "0-1", "1/2-1/2", "*"]  # Possible outcomes

    return {
        "Event": random.choice(events),
        "Site": random.choice(locations),
        "Date": f"{random.randint(2000, 2023)}.{random.randint(1, 12):02d}.{random.randint(1, 31):02d}",
        "Round": str(random.randint(1, 10)),
        "White": random_user_id(),
        "Black": random_user_id(),
        "Opening": random.choice(openings),
        "WhiteElo": str(ratings[0]),
        "BlackElo": str(ratings[1]),
        "Result": random.choice(results),
        "Annotator": "AI Assistant",
        "Variation": random.choice(["Main Line", "Alternative Line", "Quiet Move"]),
        "EventDate": f"{random.randint(2000, 2023)}.{random.randint(1, 12):02d}.{random.randint(1, 31):02d}",
        "TimeControl": random.choice(["5+0", "10+0", "15+10", "30+0"])
    }

def encode(file_path: str):
    # Read binary of file
    print("Reading file...")
    file_bytes = list(open(file_path, "rb").read())

    # Record number of bits in file
    file_bits_count = len(file_bytes) * 8

    # Convert file to chess moves
    print("\nEncoding file...")
    output_pgns = []
    file_bit_index = 0
    chess_board = Board()

    while True:
        legal_moves = list(chess_board.generate_legal_moves())
        move_bits = {}
        max_binary_length = min(int(log2(len(legal_moves))), file_bits_count - file_bit_index)

        for index, legal_move in enumerate(legal_moves):
            move_binary = to_binary_string(index, max_binary_length)
            if len(move_binary) > max_binary_length:
                break
            move_bits[legal_move.uci()] = move_binary

        closest_byte_index = file_bit_index // 8
        file_chunk_pool = "".join([
            to_binary_string(byte, 8)
            for byte in file_bytes[closest_byte_index:closest_byte_index + 2]
        ])

        next_file_chunk = file_chunk_pool[file_bit_index % 8:file_bit_index % 8 + max_binary_length]

        for move_uci in move_bits:
            move_binary = move_bits[move_uci]
            if move_binary == next_file_chunk:
                chess_board.push_uci(move_uci)
                break

        file_bit_index += max_binary_length
        eof_reached = file_bit_index >= file_bits_count

        if (
            chess_board.legal_moves.count() <= 1
            or chess_board.is_insufficient_material()
            or chess_board.can_claim_draw()
            or eof_reached
        ):
            pgn_board = pgn.Game()
            # Add randomized metadata
            metadata = random_metadata()
            for key, value in metadata.items():
                pgn_board.headers[key] = value
            pgn_board.add_line(chess_board.move_stack)
            output_pgns.append(str(pgn_board))
            chess_board.reset()

        if eof_reached:
            break

    print(f"\nSuccessfully converted file to PGN with {len(output_pgns)} game(s) ")
    return "\n\n".join(output_pgns)