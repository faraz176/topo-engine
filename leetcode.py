



# Sorts the pair so that (A, B) and (B, A) are treated the same
def canonical_pair(a, b):
    return tuple(sorted((a, b)))



from collections import defaultdict

def count_redundant_edges(edge_list):
    counts = defaultdict(int)

    for a, b in edge_list:
        key = canonical_pair(a, b)
        counts[key] += 1

    return counts


dup_set = [('A','B'), ('A','B'), ('B','A'), ('A','C')]

counts = count_redundant_edges(dup_set)

print(counts)






