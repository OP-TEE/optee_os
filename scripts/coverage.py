#!/usr/bin/env python3

# This script will create the coverage report given the coverage notes and data

import sys  # Handle exit status
import os  # Interact with PATH env variable and filesystem
import argparse  # Handle command line
import logging  # Logging
import distutils.dir_util  # Copy of tree
import subprocess  # Call lcov and genhtml
from pathlib import Path  # Glob on gcda and gcno


def find_binary(logger, bin_name, proposed_bin_path):
    """
    Finds a binary.

    :param      bin_name:  The bin name
    :type       bin_name:  string

    Return the path to the binary
    """

    # Check path passed as argument
    if proposed_bin_path is not None:
        if os.path.isfile(proposed_bin_path):
            return proposed_bin_path

    # Get PATH variable
    pathvar = os.environ['PATH']
    paths = pathvar.split(os.pathsep)

    # Loop through paths
    for path in paths:
        filepath = os.path.join(path, bin_name)

        # Try to find the file
        if os.path.isfile(filepath):
            return filepath

    logger.warning("Could not find {} in {}".format(bin_name, paths))

    # Raise exception
    raise FileNotFoundError('{}'.format(bin_name))


def main():
    cwd = os.getcwd()

    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger("coverage")

    default_gcov = "gcov"
    default_lcov = "lcov"
    default_genhtml = "genhtml"
    default_browser = "firefox"

    p = argparse.ArgumentParser(description='Process coverage data generated \
                                to create coverage result along with an HTML \
                                output')

    g1 = p.add_argument_group("Information about the analysis")
    g1.add_argument("--uc", help="Name of the Use Case", type=str,
                    default="my_uc")
    g1.add_argument("--info", help="Name of the info file to create", type=str)
    g1.add_argument("--outdir", help="Path to the directory for analysis",
                    type=str)
    g1.add_argument("--html", help="Generate HTML output", action='store_true')
    g1.add_argument("--view", help="View HTML output in browser",
                    action='store_true')
    g1.add_argument("--src_dir", help="Top dir of the sources", type=str,
                    required=True)

    g2 = p.add_argument_group("Coverage material generated")
    g2.add_argument("--notes", help="Directory containing the coverage notes",
                    type=str, required=True)
    g2.add_argument("--data", help="Directory containing the coverage data",
                    type=str, required=True)

    g3 = p.add_argument_group("External tools")
    g3.add_argument("--gcov", help="Path to the gcov binary", type=str,
                    default=default_gcov)
    g3.add_argument("--lcov", help="Path to lcov binary", type=str,
                    default=default_lcov)
    g3.add_argument("--genhtml", help="Path to genhtml binary", type=str,
                    default=default_genhtml)
    g3.add_argument("--browser", help="Path to browser binary", type=str,
                    default=default_browser)

    p.add_argument("-v", "--verbose", help="verbose mode", action='store_true')

    # Parse the command line
    args = p.parse_args()

    if args.verbose:
        logger.setLevel(logging.DEBUG)

    logger.debug("Check analysis parameters")
    logger.info("Use case name: {}".format(args.uc))

    dir_analysis = (args.outdir if args.outdir is not None
                    else "{}/{}".format(cwd, args.uc))
    logger.info("Analysis directory: {}".format(dir_analysis))

    info_filename = (args.info if args.info is not None
                     else "{}.info".format(args.uc))
    logger.info("Information filename: {}".format(info_filename))

    info_filepath = "{}/{}".format(dir_analysis, info_filename)

    logger.debug("Check coverage notes directory")
    if not os.path.isdir(args.notes):
        raise NotADirectoryError(args.notes)
    logger.info("Directory containing notes: {}".format(args.notes))

    logger.debug("Check coverage data directory")
    if not os.path.isdir(args.data):
        raise NotADirectoryError(args.data)
    logger.info("Directory containing data: {}".format(args.data))

    logger.debug("Check source directory")
    if not os.path.isdir(args.src_dir):
        raise NotADirectoryError(args.src_dir)
    logger.info("Directory of sources: {}".format(args.src_dir))

    logger.debug("Check external tools")
    logger.debug("Set gcov binary")
    gcov_bin = find_binary(l, default_gcov, args.gcov)
    logger.info("Binary for gcov: {}".format(gcov_bin))

    logger.debug("Set lcov binary")
    lcov_bin = find_binary(l, default_lcov, args.lcov)
    logger.info("Binary for lcov: {}".format(lcov_bin))

    if args.html:
        logger.debug("Set genhtml binary")
        genhtml_bin = find_binary(l, default_genhtml, args.genhtml)
        logger.info("Binary for genhtml: {}".format(genhtml_bin))

        if args.view:
            logger.debug("Set browser binary")
            browser_bin = find_binary(l, default_browser, args.genhtml)
            logger.info("Binary for genhtml: {}".format(genhtml_bin))

    logger.debug("Create analysis directory")
    os.mkdir(dir_analysis)
    logger.info("Analysis directory: {}".format(dir_analysis))

    logger.debug("Copy notes")
    distutils.dir_util.copy_tree(args.notes, dir_analysis)
    logger.debug("Copy notes done")

    logger.debug("Copy data")
    distutils.dir_util.copy_tree(args.data, dir_analysis)
    logger.debug("Copy data done")

    logger.debug("Check that the gcno are along the gcda")
    logger.debug("Search for all the gcda")
    gcda_files = list(Path(dir_analysis).rglob('*.gcda'))

    if not gcda_files:
        raise FileNotFoundError("No gcda files can be found in {}".
                                format(dir_analysis))

    for gcda_file in gcda_files:
        component = Path(gcda_file).with_suffix('')
        gcno_file_exp = str(component) + ".gcno"
        logger.debug("gcda: {}, looking for {}".format(gcda_file,
                     gcno_file_exp))

        if not os.path.isfile(gcno_file_exp):
            logger.error("{} does not exists".format(gcno_file_exp))
            gcno_file = os.path.basename(gcno_file_exp)
            gcno_files = list(Path(dir_analysis).rglob(gcno_file))

            if not gcno_files:
                raise FileNotFoundError("{} could not be found in {}".
                                        format(gcno_file, dir_analysis))
            else:
                raise FileNotFoundError('{} not along {}, located at {}'.
                                        format(gcno_file_exp, gcda_file,
                                               gcno_files[0]))

    run_analysis_cmd = [lcov_bin, "--capture", "--directory", dir_analysis,
                        "--gcov-tool", gcov_bin, "--output-file",
                        info_filepath]
    logger.debug("Analysis command: {}".format(run_analysis_cmd))

    logger.debug("Run the analysis")
    run_analysis = subprocess.check_output(run_analysis_cmd,
                                           stderr=subprocess.STDOUT)

    gcov_errors = ["skipping", "did not produce any data for"]

    logger.debug("Check analysis output")
    for line in run_analysis.decode("utf-8").splitlines():
        for error in gcov_errors:
            if error in line:
                raise RuntimeError(line)

    logger.info("Analysis done, information file: {}".format(info_filepath))

    if args.html:
        html_folder = "{}/html".format(dir_analysis)

        generate_html_cmd = [genhtml_bin, "--prefix", args.src_dir, "--legend",
                             "--title", args.uc, "--output-directory",
                             html_folder, info_filepath]
        logger.debug("HTML generation command: {}".format(run_analysis_cmd))

        logger.debug("Create HTML output")
        generate_html = subprocess.check_output(generate_html_cmd)

        logger.info("HTML generation done, output: {}".format(html_folder))

        html_index = "{}/index.html".format(html_folder)
        logger.info("HTML index file: {}".format(html_index))

        if args.view:
            view_cmd = [browser_bin, html_index]

            logger.debug("Show HTML output in browser")
            logger.info("View HTML in browser: {}".format(view_cmd))
            subprocess.run(view_cmd)

    sys.exit(0)


if __name__ == "__main__":
    main()
