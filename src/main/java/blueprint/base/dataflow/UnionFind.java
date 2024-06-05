package blueprint.base.dataflow;

import blueprint.utils.Logging;

import java.util.HashSet;
import java.util.Map;
import java.util.HashMap;
import java.util.Set;

public class UnionFind<T> {
    private final Map<T, T> parent = new HashMap<>();
    private final Map<T, Integer> rank = new HashMap<>();
    private final Map<T, Set<T>> clusters = new HashMap<>();

    private void ensureSet(T element) {
        if (!parent.containsKey(element)) {
            parent.put(element, element);
            rank.put(element, 0);

            HashSet<T> newSet = new HashSet<>();
            newSet.add(element);
            clusters.put(element, newSet);
        }
    }

    public T find(T s) {
        ensureSet(s);
        if (parent.get(s) != s) {
            parent.put(s, find(parent.get(s)));
        }
        return parent.get(s);
    }

    public void union(T x, T y) {
        ensureSet(x);
        ensureSet(y);

        T xRoot = find(x);
        T yRoot = find(y);

        if (xRoot == yRoot) {
            Logging.debug("UnionFind", String.format("%s and %s have already in the same cluster", x, y));
            return;
        }
        if (rank.get(xRoot) < rank.get(yRoot)) {
            parent.put(xRoot, yRoot);
            // add all elements in a larger root
            clusters.get(yRoot).addAll(clusters.get(xRoot));
            clusters.remove(xRoot);
        } else if (rank.get(xRoot) > rank.get(yRoot)) {
            parent.put(yRoot, xRoot);
            clusters.get(xRoot).addAll(clusters.get(yRoot));
            clusters.remove(yRoot);
        } else {
            parent.put(yRoot, xRoot);
            clusters.get(xRoot).addAll(clusters.get(yRoot));
            clusters.remove(yRoot);
            rank.put(xRoot, rank.get(xRoot) + 1);
        }
    }

    public Map<T, Set<T>> getAllClusters() {
        return clusters;
    }

    public Set<T> getCluster(T element) {
        return clusters.get(find(element));
    }


    public void mergeByAccessed(UnionFind<T> other, Set<T> accessedExpr) {
        for (T expr: accessedExpr) {
            // parent is a Map from expr to its parent node in union-find.
            // in union-find, each element is stored in parent's key set.
            if (other.parent.containsKey(expr)) {
                T rootInOther = other.find(expr);
                Set<T> clusterToMerge = other.clusters.get(rootInOther);
                for (T member: clusterToMerge) {
                    if (accessedExpr.contains(member) && member != expr) {
                        Logging.info("UnionFind", String.format("Confirm union between %s and %s in may type alias", expr, member));
                        union(expr, member);
                    }
                }
            }
        }
    }
}
