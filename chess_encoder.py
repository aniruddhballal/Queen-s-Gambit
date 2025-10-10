import random
from math import log2
from chess import pgn, Board
from io import StringIO

class ChessEncoder:
    @staticmethod
    def no_to_bin_str(num: int, bits: int):
        binary = bin(num)[2:]
        return binary.zfill(bits)
    
    @staticmethod
    def random_user_id():
        return f"{random.randint(100000, 999999)}"
    
    @staticmethod
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
        
        white_elo = random.randint(200, 3000)
        lower_bound = int(white_elo * 0.9)
        upper_bound = int(white_elo * 1.1)
        black_elo = random.randint(lower_bound, upper_bound)
        results = ["1-0", "0-1", "1/2-1/2", "*"]

        metadata = {
            "Event": random.choice(events),
            "Site": random.choice(locations),
            "Date": f"{random.randint(1990, 2023)}.{random.randint(1, 12):02d}.{random.randint(1, 31):02d}",
            "Round": str(random.randint(1, 15)),
            "White": ChessEncoder.random_user_id(),
            "Black": ChessEncoder.random_user_id(),
            "ExpectedOpening": random.choice(expected_openings),
            "WhiteElo": str(white_elo),
            "BlackElo": str(black_elo),
            "Result": random.choice(results),
            "Annotator": ChessEncoder.random_user_id(),
            "Variation": random.choice(["Main Line", "Alternative Line", "Quiet Move", "Aggressive Line", "Theoretical Novelty"]),
            "EventDate": f"{random.randint(1990, 2023)}.{random.randint(1, 12):02d}.{random.randint(1, 31):02d}",
            "TimeControl": random.choice(["3+2", "5+0", "10+0", "15+10", "30+0", "60+0", "90+30"])
        }

        keys_to_hide = random.sample(list(metadata.keys()), random.randint(1, len(metadata) // 2))
        for key in keys_to_hide:
            metadata[key] = "Hidden"

        return metadata
    
    @staticmethod
    def make_gambit(sample_file: str):
        print("Making the Gambit...")
        bittify = (255).bit_length()

        with open(sample_file, "rb") as f:
            file01 = list(f.read())

        bits = bittify * len(file01)
        pgnlist = []
        current_pos = 0
        board_instance = Board()

        while True:
            gen_moves = board_instance.generate_legal_moves()
            moves_list = list(board_instance.generate_legal_moves())
            log_length = int(log2(len(moves_list)))
            remaining_bits = bits - current_pos
            bits_req = min(log_length, remaining_bits)

            bits_map_set_of_moves = {}
            valid_moves = {
                anti_illegal_move.uci(): ChessEncoder.no_to_bin_str(i, bits_req)
                for i, anti_illegal_move in enumerate(gen_moves)
                if len(ChessEncoder.no_to_bin_str(i, bits_req)) <= bits_req
            }

            bits_map_set_of_moves.update(valid_moves)
            next_byte_i = current_pos // bittify
            strs = ''

            for byte1 in file01[next_byte_i:next_byte_i + 2]:
                binary_string = ChessEncoder.no_to_bin_str(byte1, bittify)
                strs += binary_string

            start_index = current_pos % bittify
            next_str = ''

            for i in range(bits_req):
                if start_index + i < len(strs):
                    next_str += strs[start_index + i]

            current_pos += bits_req

            for movei in bits_map_set_of_moves:
                bits_mapped = bits_map_set_of_moves[movei]
                if bits_mapped == next_str:
                    board_instance.push_uci(movei)
                    break
            
            if (board_instance.legal_moves.count() <= 1.5 or current_pos >= bits):
                pgn_ = pgn.Game()
                metadata = ChessEncoder.random_metadata()

                for key, value in metadata.items():
                    pgn_.headers[key] = value
                
                pgn_.add_line(board_instance.move_stack)
                pgnlist.append(str(pgn_))
                board_instance.reset()

            if current_pos >= bits:
                break

        print("Gambit done.")
        return "\n\n".join(pgnlist)
    
    @staticmethod
    def listify_pgns(pgn_string: str):
        games = []
        pgn_stream = StringIO(pgn_string)
        game = pgn.read_game(pgn_stream)
        
        while game:
            games.append(game)
            game = pgn.read_game(pgn_stream)
        
        return games
    
    @staticmethod
    def undo_gambit(games_pgn: str, output_og_sample_file: str):
        print("Undoing the Gambit...")
        moves_processed = 0
        bittify = (255).bit_length()
        pgn_list = ChessEncoder.listify_pgns(games_pgn)
        iterable_games = list(pgn_list)

        op_dec_file = open(output_og_sample_file, "wb")
        try:
            dec_data = ""
            for pgn_g_num, g in enumerate(iterable_games):
                board_instance = Board()
                moves_list = list(g.mainline_moves())
                moves_processed += len(moves_list)

                for move_i, iterable_moves in enumerate(moves_list):
                    moves_possible = board_instance.generate_legal_moves()
                    strs = [move_iterable.uci() for move_iterable in moves_possible]
                    indexify_move = strs.index(iterable_moves.uci())
                    pad_indexed_bin = bin(indexify_move)[2:]

                    game_over = (pgn_g_num == len(iterable_games) - 1)
                    last_move = (move_i == len(moves_list) - 1)

                    if game_over and last_move:
                        moves_count = len(strs)
                        log_length = int(log2(moves_count))
                        remaining_bits = bittify - (len(dec_data) % bittify)
                        bits_req = min(log_length, remaining_bits)
                    else:
                        moves_count = len(strs)
                        bits_req = int(log2(moves_count))

                    test_pad = bits_req - len(pad_indexed_bin)
                    non_neg_padding = max(0, test_pad)
                    padding = "0" * non_neg_padding
                    pad_indexed_bin = padding + pad_indexed_bin

                    next_move = iterable_moves.uci()
                    board_instance.push_uci(next_move)
                    dec_data += pad_indexed_bin

                    if len(dec_data) % bittify == 0:
                        byte_values = []
                        num_chunks = len(dec_data) / bittify
                        i = 0

                        while i < int(num_chunks):
                            start_index = i * bittify
                            end_index = start_index + bittify

                            chunk = ''
                            for indexify_move in range(start_index, end_index):
                                chunk += dec_data[indexify_move]

                            byte_value = 0
                            for bit in chunk:
                                byte_value = byte_value * 2 + int(bit)

                            byte_values.append(byte_value)
                            i += 1

                        for byte_value in byte_values:
                            byte = byte_value.to_bytes(1, byteorder='big')
                            op_dec_file.write(byte)

                        dec_data = ""
        finally:
            op_dec_file.close()
        print("Gambit undone.")