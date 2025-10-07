from math import log2
from chess import pgn, Board
from util import get_pgn_games

def decode(pgn_string: str, output_file_path: str):
    total_move_count = 0

    # Load games from PGN string
    games: list[pgn.Game] = get_pgn_games(pgn_string)

    # Prepare to write to output file
    with open(output_file_path, "wb") as output_file:
        output_data = ""

        for game_index, game in enumerate(games):
            chess_board = Board()
            game_moves = list(game.mainline_moves())
            total_move_count += len(game_moves)

            for move_index, move in enumerate(game_moves):
                # Get UCIs of legal moves in current position
                legal_move_ucis = [
                    legal_move.uci()
                    for legal_move in list(chess_board.generate_legal_moves())
                ]

                # Get binary of the move played
                move_binary = bin(legal_move_ucis.index(move.uci()))[2:]

                # Determine max binary length
                if (game_index == len(games) - 1 and move_index == len(game_moves) - 1):
                    max_binary_length = min(int(log2(len(legal_move_ucis))), 8 - (len(output_data) % 8))
                else:
                    max_binary_length = int(log2(len(legal_move_ucis)))

                # Pad move binary to meet max binary length
                required_padding = max(0, max_binary_length - len(move_binary))
                move_binary = ("0" * required_padding) + move_binary

                # Play move on board
                chess_board.push_uci(move.uci())

                # Add move binary to output data string
                output_data += move_binary

                # If output binary pool is a multiple of 8, flush it to file
                if len(output_data) % 8 == 0:
                    output_file.write(
                        bytes([
                            int(output_data[i * 8: i * 8 + 8], 2)
                            for i in range(len(output_data) // 8)
                        ])
                    )
                    output_data = ""

    print(
        "\nSuccessfully decoded PGN with "
        + f"{len(games)} game(s), {total_move_count} total move(s) "
    )