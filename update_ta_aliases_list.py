# import json  # for testing purposes
from ta_list_methods import get_all_ta_from_act, get_all_alias_facts_from_act, add_ta_to_map, add_ta_alias_to_map, create_config


def main():

    # gets all ta names from objects(as a set of strings) and facts(as a set with tuples of two strings) in ACT
    ta = get_all_ta_from_act()

    # gets all threat actor aliases from act platform

    ta_aliases = get_all_alias_facts_from_act()

    # save ta and ta_aliases to json test file
    # with open('objects.json', 'w') as outfile:
#        outfile.write(json.dumps(list(ta)))

#    with open('facts.json', 'w') as outfile:
#        outfile.write(json.dumps(list(ta_aliases)))

    # adds all ta names from threatActor objects from ACT into ta_map
    ta_map = add_ta_to_map(ta)

    # adds all ta names from alias-facts in ACT to the ta_map
    ta_map_with_aliases = add_ta_alias_to_map(ta_aliases, ta_map)

    # creates a file "aliases_new.cfg" including all the content from ta_map and the existing file "aliases.cfg".
    create_config(ta_map_with_aliases)


# https://stackoverflow.com/questions/419163/what-does-if-name-main-do
if __name__ == "__main__":

    main()
