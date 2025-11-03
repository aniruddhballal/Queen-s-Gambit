"""
Chess-based decoding utilities.
Decodes chess game moves (PGN format) back into binary data.
"""

import time
from math import log2
from chess import pgn, Board
from io import StringIO


def listify_pgns(pgn_string: str):
    """
    Parse a PGN string into a list of chess game objects.
    
    Args:
        pgn_string: str - String containing one or more PGN games
        
    Returns:
        List of chess.pgn.Game objects
    """
    games = []
    pgn_stream = StringIO(pgn_string)
    game = pgn.read_game(pgn_stream)
    
    while game:
        games.append(game)
        game = pgn.read_game(pgn_stream)
    
    return games


def undo_gambit(games_pgn: str, output_og_sample_file: str, session_id: str = None, progress_data: dict = None):
    """
    Decode chess games (PGN format) back into the original file.
    
    Args:
        games_pgn: str - String containing PGN-formatted chess games
        output_og_sample_file: str - Path where decoded file should be saved
        session_id: str - Optional session ID for progress tracking
        progress_data: dict - Optional dictionary to store progress updates
    """
    print("Undoing the Gambit...")
    moves_processed = 0
    bittify = (255).bit_length()
    
    pgn_list = listify_pgns(games_pgn)
    iterable_games = list(pgn_list)
    total_games = len(iterable_games)
    start_time = time.time()

    op_dec_file = open(output_og_sample_file, "wb")
    try:
        dec_data = ""
        for pgn_g_num, g in enumerate(iterable_games):
            # Update progress
            if session_id and progress_data is not None:
                progress_percentage = ((pgn_g_num + 1) / total_games) * 100
                elapsed_time = time.time() - start_time
                games_per_sec = (pgn_g_num + 1) / elapsed_time if elapsed_time > 0 else 0
                progress_data[session_id] = {
                    'current': pgn_g_num + 1,
                    'total': total_games,
                    'percentage': round(progress_percentage, 2),
                    'stage': 'decoding',
                    'speed': round(games_per_sec, 2),
                    'elapsed_time': round(elapsed_time, 2)
                }

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
        # Set progress to 100% when done
        if session_id and progress_data is not None:
            elapsed_time = time.time() - start_time
            avg_speed = total_games / elapsed_time if elapsed_time > 0 else 0
            progress_data[session_id] = {
                'current': total_games,
                'total': total_games,
                'percentage': 100.0,
                'stage': 'decoding',
                'speed': round(avg_speed, 2),
                'elapsed_time': round(elapsed_time, 2)
            }
    print("Gambit undone.")