import chess.pgn

# Function to analyze the game result based on the final board position
def analyze_result(board):
    if board.is_checkmate():
        # Check who delivered checkmate
        return "1-0" if board.turn == chess.BLACK else "0-1"
    elif board.is_stalemate():
        return "1/2-1/2 (Stalemate)"
    elif board.is_insufficient_material():
        return "1/2-1/2 (Insufficient Material)"
    elif board.is_seventyfive_moves():
        return "1/2-1/2 (75-move rule)"
    elif board.is_fivefold_repetition():
        return "1/2-1/2 (Fivefold Repetition)"
    else:
        return "* (Game in progress or no decisive outcome)"

# Load the PGN file and read the game moves
pgn_file_path = "samplegame.pgn"  # Replace with your PGN file path
with open(pgn_file_path) as pgn_file:
    game = chess.pgn.read_game(pgn_file)

# Initialize a board to play through the moves
board = game.board()

# Play all moves in the mainline
for move in game.mainline_moves():
    board.push(move)

# Analyze the final board position to determine the result
result = analyze_result(board)
print("Game result:", result)



pgn_file_path = "samplegame.pgn"  # Replace with your PGN file path
with open(pgn_file_path) as pgn_file:
    # Read each game in the PGN file
    while True:
        game = chess.pgn.read_game(pgn_file)
        if game is None:
            break  # End of file

        # Count moves
        move_count = sum(1 for _ in game.mainline_moves())
        print(f"Game ended after {move_count} moves")

        # Print the last move in the game
        board = game.board()
        for move in game.mainline_moves():
            board.push(move)
        
        # Show the final position and the last move
        print("Final board position:")
        print(board)
        print("Last move:", board.peek())  # Shows the last move played
