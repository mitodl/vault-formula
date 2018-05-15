import logging

log = logging.getLogger(__name__)


class DuplicateElement(Exception):
    pass


class UniqueSet(set):
    def add(self, elem):
        if elem in self:
            raise DuplicateElement('%s already exists in the set', elem)
        return super(UniqueSet, self).add(elem)


def traverse_leaf_nodes(dict_or_list, leaf_filter=lambda x: True):
    """Walk a data structure and perform an action on
    leaf nodes matching a filter.

    :param dict_or_list: Arbitrarily nested data structure to traverse
    :returns: List of 3-tuples (leaf_node, leaf_index, leaf_container)
    :rtype: List

    """
    processed_objects = UniqueSet()
    processed_objects.add(id(dict_or_list))
    leaf_nodes = []

    def _is_leaf_node(element):
        return not isinstance(element, (list, dict, set, tuple))

    def _process_sequence(sequence_object,
                          leaf_filter=None):
        for index, element in enumerate(sequence_object):
            try:
                processed_objects.add(id(element))
            except DuplicateElement:
                continue
            if _is_leaf_node(element):
                if not leaf_filter(element):
                    continue
                leaf_nodes.append((element, index, sequence_object))
            else:
                _process_router(element, leaf_filter)

    def _process_dict(dict_object,
                      leaf_filter=None):
        for k, v in dict_object.items():
            try:
                processed_objects.add(id(v))
            except DuplicateElement:
                continue
            if _is_leaf_node(v):
                if not leaf_filter(v):
                    continue
                leaf_nodes.append((v, k, dict_object))
            else:
                _process_router(v, leaf_filter)

    def _process_router(dict_or_list, leaf_filter=None):
        if isinstance(dict_or_list, dict):
            _process_dict(dict_or_list, leaf_filter)
        else:
            _process_sequence(dict_or_list, leaf_filter)

    _process_router(dict_or_list, leaf_filter)
    return leaf_nodes
