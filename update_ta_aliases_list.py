import act
from ta_list_methods import *


def main():

    # sets the url for the act platform and the userid.
    baseurl = "http://osl-act-dev-trunk1.mnemonic.no:8080"
    userid = 3

    # creates an API agent
    c = act.Act(baseurl, userid, log_level="info")

    # gets all ta names from objects(as a set of strings) and facts(as a set with tuples of two strings) in ACT
    ta = get_all_ta_from_act(c)

    ta_aliases = get_all_alias_facts_from_act(c)

    # adds all ta names from threatActor objects from ACT into ta_map
    ta_map = add_ta_to_map(ta)

    # adds all ta names from alias-facts in ACT to the ta_map
    ta_map_with_aliases = add_ta_alias_to_map(ta_aliases, ta_map)

    # creates a file "aliases_new.cfg" including all the content from ta_map and the existing file "aliases.cfg".
    create_config(ta_map_with_aliases)


# https://stackoverflow.com/questions/419163/what-does-if-name-main-do
if __name__ == "__main__":

    main()
