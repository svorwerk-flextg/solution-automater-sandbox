import subprocess
import sys
import os
import argparse

def check_git_state_clean():
    """
    Check if git state has uncommitted changes.

    Returns:
        tuple: (is_clean, details_dict)
            - is_clean (bool): True if git state is clean
            - details_dict (dict): Details about git state
    """
    details = {}
    try:
        git_status = (
            subprocess.check_output(["git", "status", "--porcelain"])
            .decode("utf-8")
            .strip()
        )
        git_is_clean = not git_status
        details = {
            "is_clean": git_is_clean,
            "status": git_status.split("\n") if git_status else [],
        }
    except (subprocess.CalledProcessError, FileNotFoundError):
        details["error"] = "Git information not available"
        git_is_clean = False
    return git_is_clean, details

def create_reproduce_command(parser, output_file, dvc_file_path=None):
    """
    Create a text file with the command to reproduce this run

    Args:
        parser (argparse.ArgumentParser): Parser object
        output_file (str): File to save reproduction command
        dvc_file_path (str, optional): Path to DVC file for checkout
    """
    git_hash = (
        subprocess.check_output(["git", "rev-parse", "HEAD"]).decode("utf-8").strip()
    )
    with open(output_file, "w") as f:
        f.write(f"git checkout {git_hash}\n")
    if dvc_file_path:
        with open(output_file, "a") as f:
            f.write(f"dvc checkout {dvc_file_path}\n")
    command = ["python"]
    script_path = sys.argv[0]
    command.append(script_path)
    args = parser.parse_args()
    default_values = {action.dest: action.default for action in parser._actions}
    store_action_args = {
        action.dest
        for action in parser._actions
        if isinstance(action, argparse._StoreTrueAction) or isinstance(action, argparse._StoreFalseAction)
    }
    for arg_name, arg_value in vars(args).items():
        if arg_value == default_values.get(arg_name):
            continue
        if arg_name in store_action_args:
            command.append(f"--{arg_name}")
        else:
            command.append(f"--{arg_name} {arg_value}")
    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    with open(output_file, "a") as f:
        f.write(" ".join(command))
