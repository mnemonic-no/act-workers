import json
import argparse
from ta_list_methods import get_all_ta_from_act, get_all_alias_facts_from_act, \
    add_ta_to_map, add_ta_alias_to_map, create_config


def parseargs():
    """ Parse arguments """
    parser = argparse.ArgumentParser(description='Updates list of threat actor \
        aliases from an ACT platform')
    parser.add_argument('--baseurl', required=True, help='URL to ACT platform \
        installation')
    parser.add_argument('--userid', required=True, help="User ID for ACT \
        platform")
    parser.add_argument('--aliasfile', required=True, help=".cfg-file with \
        existing threat actor aliases")
    parser.add_argument('--newaliasfile', required=True, help="name of \
        .cfg-file with updated list of threat actor aliases")
    parser.add_argument('--output-json', action='store_true', help="Enable \
        this flag if json testfiles should be created.")

    return parser.parse_args()


def main():
    """main function"""

    args = parseargs()

    # gets all ta names from objects(as a set of strings) and facts(as a
    # set with tuples of two strings) in ACT.

    threatactors = get_all_ta_from_act(args.baseurl, args.userid)

    # gets all threat actor aliases from act platform

    ta_aliases = get_all_alias_facts_from_act(args.baseurl, args.userid)

    # save ta and ta_aliases to json test file
    if args.output_json:
        with open('test/objects.json', 'w') as outfile:
            outfile.write(json.dumps(list(threatactors)))

        with open('test/facts.json', 'w') as outfile:
            outfile.write(json.dumps(list(ta_aliases)))

    # adds all ta names from threatActor objects from ACT into ta_map
    ta_map = add_ta_to_map(threatactors)

    # adds all ta names from alias-facts in ACT to the ta_map
    ta_map_with_aliases = add_ta_alias_to_map(ta_aliases, ta_map)

    # creates a new .cfg-file including all the content from ta_map
    # and the existing cfg.-file from arguments.
    create_config(ta_map_with_aliases, args.aliasfile, args.newaliasfile)


if __name__ == "__main__":

    main()
