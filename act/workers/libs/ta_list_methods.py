# -*- coding: utf-8 -*-
from collections import defaultdict
import act


def create_api_agent(baseurl, userid):
    """ creates an ACT API agent """
    c = act.Act(baseurl, userid, log_level="info")
    return c


def get_all_ta_from_act(baseurl, userid):
    """ gets set of all threat actor names in the ACT platform.
    Note that limit is set to 1000. """

    objects = create_api_agent(baseurl,
                               userid).object_search(object_type=["threatActor"], limit=1000)

    ta_set = set()

    for x in objects:
        ta_set.add(x.value)

    return list(ta_set)


def get_all_alias_facts_from_act(baseurl, userid):
    """ gets set of all bindings between threat actor and threat actor aliases
    from ACT. Note that limit is set to 1000. """

    facts = create_api_agent(baseurl, userid).\
        fact_search(object_type=["threatActor"],
                    fact_type=["threatActorAlias"], limit=1000)

    ta_set_facts = set()
    for fa in facts:
        ta1, ta2 = fa.source_object.value, fa.destination_object.value
        ta_set_facts.add((ta1, ta2))

    return ta_set_facts


def add_ta_to_map(ta_set):
    """ adds all threat actor names given in a set to a map.
    The map is a defaultdict with sets, each set containing a key and all
    relevant aliases for that key as values. """

    ta_map = defaultdict(set)
    for ta in ta_set:
        ta_map[ta].add(ta)
    return ta_map


def add_ta_alias_to_map(ta_aliases, ta_map):
    """ adds alias to the ta_map. Needs arguments ta_map defaultdict with sets,
    and tuples with two strings in each. Assumes that all threat actors are
    already in the ta_map. """

    for tup in ta_aliases:
        ta1, ta2 = tup
        s = ta_map[ta1]
        s.update(ta_map[ta2])
        # point key of all elements of the set to the same set.
        for x in s:
            ta_map[x] = s

    return ta_map


def decide_on_key(k_decide, v_decide, config_dict):
    """ checks with old config file to decide on key in new config file. """

    # if key is within the keys in the current configfile,
    # then return that value from v as key and the rest as aliases.
    if k_decide in config_dict[0]:
        v_decide.remove(k_decide)
        return k_decide, v_decide

    # if the key is within the aliases of another key, then return the key of
    # the set where the value was found and remove that value from the set.
    for kk, vv in config_dict.items():
        if k_decide in vv and kk in v_decide:
            v_decide.remove(kk)

            return kk, v_decide

    # if the key is not a key already, then just choose one from the set v,
    # and set the rest as aliases.
    v_decide.remove(k_decide)

    return k_decide, v_decide


def create_config(ta_map, aliasfile, newaliasfile):
    """ creates config file from ta_map, defaultdict with set."""
    def config_split(l):
        k, v = l.split(":")
        return k, [x.strip() for x in v.split(",")]

    config_dict = defaultdict(set)

    with open(aliasfile, "r") as config:
        for l in config:
            k, v = config_split(l)
            config_dict[k] = v

    with open(newaliasfile, "w") as config:

        config.truncate()

        while ta_map:
            k, v = ta_map.popitem()

            if len(v) == 1:
                config.write(k + ":\n")
            else:
                k_decide_key = k[:]
                v_decide_key = set(v)
                ta_name, ta_aliases = decide_on_key(k_decide_key, v_decide_key,
                                                    config_dict)
                config.write("{}: {}\n".format(ta_name, ",".join(ta_aliases)))
                v.remove(k)
                for x in v:
                    ta_map.pop(x)
