package blueprint.base.dataflow.typeAlias;

import blueprint.base.dataflow.SymbolExpr.SymbolExprManager;
import blueprint.base.dataflow.constraints.TypeConstraint;
import blueprint.utils.Logging;
import org.jgrapht.alg.shortestpath.AllDirectedPaths;

import java.io.FileWriter;
import java.util.*;

public class TypeAliasPathManager<T> {
    public TypeAliasGraph<T> graph;
    public boolean hasSrcSink = true;
    public final Set<T> source;
    public final Set<T> sink;

    public final Set<TypeAliasPath<T>> allPaths;
    public final Map<T, Set<TypeAliasPath<T>>> nodeToPathsMap;
    public final Map<T, Map<T, Set<TypeAliasPath<T>>>> srcSinkToPathsMap;

    public final Map<T, Set<TypeConstraint>> nodeToConstraints;

    /** fields for conflict nodes */
    public final Set<T> conflictNodes = new HashSet<>();
    public final Set<List<T>> conflictNodesCommonPaths = new HashSet<>();
    public final Map<T, Set<T>> excludeEdges = new HashMap<>();
    public final Set<TypeAliasGraph.TypeAliasEdge> removedEdges = new HashSet<>();

    public TypeAliasPathManager(TypeAliasGraph<T> graph) {
        this.graph = graph;
        this.source = new HashSet<>();
        this.sink = new HashSet<>();
        this.allPaths = new HashSet<>();
        this.nodeToPathsMap = new HashMap<>();
        this.srcSinkToPathsMap = new HashMap<>();
        this.nodeToConstraints = new HashMap<>();
    }

    public void build() {
        findSources();
        findSinks();
        if (source.isEmpty() || sink.isEmpty()) {
            hasSrcSink = false;
            return;
        }

        if (hasSrcSink) {
            findAllPathFromSrcToSink();
        }

        for (var path: allPaths) {
            updateNodeToPathsMap(path);
        }
    }

    /**
     * Try merge TypeConstraints using nodes in one path
     * IMPORTANT: This Function should be called after all Graph's pathManager built
     */
    public void tryMergeByPath(SymbolExprManager exprManager) {
        var workList = new LinkedList<>(allPaths);

        while (!workList.isEmpty()) {
            var path = workList.poll();
            Logging.info("TypeAliasPathManager", "============================================== start ==============================================\n");
            Logging.info("TypeAliasPathManager", String.format("Try merge by path: %s", path));
            var hasConflict = path.tryMergeOnPath(exprManager);
            if (hasConflict.isPresent()) {
                var conflictNode = hasConflict.get();
                // Split Path
                var splitPaths = path.splitPathFromNode(conflictNode);
                var firstPath = splitPaths.getKey();
                var secondPath = splitPaths.getValue();

                Logging.info("TypeAliasPathManager", String.format("Split new path: %s", firstPath));
                Logging.info("TypeAliasPathManager", String.format("Split new path: %s", secondPath));

                // Update related data structures
                updateNewPath(firstPath);
                updateNewPath(secondPath);

                // Add new paths into workList
                workList.add(firstPath);
                workList.add(secondPath);
            }
            Logging.info("TypeAliasPathManager", "============================================== end ==============================================\n");
        }


        // Post handle
        for (var path: allPaths) {
            if (path.hasConflict) {
                continue;
            }
            if (path.finalConstraint.isEmpty()) {
                path.noComposite = true;
            }
        }
    }

    // Try merge paths from same source, them propagate TypeConstraints to each node start from this source
    // Because there may have some node with paths from different source, we then handle them in next step
    public void tryMergePathsFromSameSource() {
        // TODO: handle path's hasConflict
        for (var src: source) {
            var mergedConstraints = new TypeConstraint();
            var pathsFromSource = getAllPathsFromSource(src);
            var hasConflict = false;
            for (var path: pathsFromSource) {
                if (path.hasConflict || path.noComposite) {
                    continue;
                }
                var noConflict = mergedConstraints.tryMerge(path.finalConstraint);
                if (!noConflict) {
                    // If there has conflict when merging different paths from same source, we do not try to
                    // merge them, and see these paths are from `different sources` and propagate TypeConstraints
                    // to each node in their path.
                    hasConflict = true;
                    Logging.warn("TypeAliasPathManager", String.format("Paths from source %s has conflict when merging path's final Constraint", src));
                    for (var p: pathsFromSource) {
                        if (p.hasConflict || p.noComposite) {
                            continue;
                        }
                        propagateConstraintByPath(p.finalConstraint, p);
                    }
                    break;
                }
            }

            if (!hasConflict) {
                // If there has no conflict when merging different paths from same source, we propagate the merged Constraints
                // to each node start from this source
                Logging.info("TypeAliasPathManager", String.format("Paths from source %s has no conflict when merging path's final Constraint", src));
                for (var path: pathsFromSource) {
                    if (path.hasConflict || path.noComposite) {
                        continue;
                    }
                    propagateConstraintByPath(mergedConstraints, path);
                }
            }
        }
    }


    /**
     * If there has multiple TypeConstraints in one node, means there has TypeConstraints
     * from different sources, we should handle them and try to merge them.
     */
    public void handleNodeConstraints() {
        for (var node: nodeToConstraints.keySet()) {
            var constraints = nodeToConstraints.get(node);
            if (constraints.size() > 1) {
                // Two Problem to solve:
                // 1. How to find which nodes need to remove edge
                // 2. which edge to remove: all edge? backward edges? forward edges?
                // 3. which type of edge to remove? CALL? DATAFLOW? or ...
                var mergedConstraints = new TypeConstraint();
                Logging.info("TypeAliasPathManager", String.format("Node has multiple TypeConstraints: %s: %d", node, constraints.size()));
                for (var path: nodeToPathsMap.get(node)) {
                    if (path.hasConflict || path.noComposite) {
                        continue;
                    }
                    Logging.info("TypeAliasPathManager", path.toString());
                }

                for (var con: constraints) {
                    var noConflict = mergedConstraints.tryMerge(con);
                    if (!noConflict) {
                        Logging.warn("TypeAliasPathManager", String.format("Conflict when merging TypeConstraints in node %s", node));

                        conflictNodes.add(node);
                        conflictNodesCommonPaths.addAll(getLongestCommonPath(nodeToPathsMap.get(node)));

                        for (var c: constraints) {
                            Logging.info("TypeAliasPathManager", c.dumpLayout(0));
                        }
                        break;
                    }
                }
            } else {
                Logging.info("TypeAliasPathManager", String.format("Node has single TypeConstraints: %s: %d", node, constraints.size()));
            }
        }
    }

    /**
     * Get the edges need to remove in TypeAliasGraph, these edges are related to conflict nodes
     * @return Set of edges need to remove
     */
    public Set<TypeAliasGraph.TypeAliasEdge> getEdgesToRemove() {
        buildExcludeEdges();

        for (var node: conflictNodes) {
            for (var edge: graph.getGraph().edgesOf(node)) {
                var src = graph.getGraph().getEdgeSource(edge);
                var dst = graph.getGraph().getEdgeTarget(edge);
                var excludeNodes = excludeEdges.get(node);
                if (excludeNodes != null && excludeNodes.contains(src) && excludeNodes.contains(dst)) {
                    continue;
                }
                removedEdges.add(edge);
                Logging.info("TypeAliasPathManager", String.format("Mark Edge to remove in TypeAliasGraph: %s ---> %s", src, dst));
            }
        }
        return removedEdges;
    }


    public void findSources() {
        for (T vertex : graph.getGraph().vertexSet()) {
            if (graph.getGraph().inDegreeOf(vertex) == 0 && graph.getGraph().outDegreeOf(vertex) > 0) {
                source.add(vertex);
            }
        }
    }

    public void findSinks() {
        for (T vertex : graph.getGraph().vertexSet()) {
            if (graph.getGraph().inDegreeOf(vertex) > 0 && graph.getGraph().outDegreeOf(vertex) == 0) {
                sink.add(vertex);
            }
        }
    }

    public void findAllPathFromSrcToSink() {
        for (T src: source) {
            for (T sk: sink) {
                var allPaths = new AllDirectedPaths<>(graph.getGraph()).getAllPaths(src, sk, true, Integer.MAX_VALUE);
                for (var path: allPaths) {
                    TypeAliasPath<T> typeAliasPath = new TypeAliasPath<>(path);
                    this.allPaths.add(typeAliasPath);
                    srcSinkToPathsMap.computeIfAbsent(src, k -> new HashMap<>()).computeIfAbsent(sk, k -> new HashSet<>()).add(typeAliasPath);
                }
            }
        }
        Logging.info("TypeAliasPathManager", String.format("Found %d paths from sources to sinks", allPaths.size()));
    }

    /**
     * Get the longest common path in given paths using binary search and sub-path's hash ...
     * @param paths Set of given paths
     * @return Set of sub-paths
     */
    public Set<List<T>> getLongestCommonPath(Set<TypeAliasPath<T>> paths) {
        int lowBound = 1;
        int highBound = Integer.MAX_VALUE;
        Map<Integer, Set<Integer>> lengthToPathHash = new HashMap<>();
        for (var path: paths) {
            highBound = Math.min(highBound, path.nodes.size());
        }

        while (lowBound <= highBound) {
            int length = (lowBound + highBound) / 2;

            // get all sub-paths with length
            for (var path: paths) {
                path.createSubPathsOfLength(length);
            }

            // check all paths if there has common sub-path by intersecting their sub-paths hash
            var firstPath = paths.iterator().next();
            var firstPathHashes = firstPath.subPathsOfLengthWithHash.get(length).keySet();
            for (var p: paths) {
                var pathHashes = p.subPathsOfLengthWithHash.get(length).keySet();
                firstPathHashes.retainAll(pathHashes);
            }

            if (firstPathHashes.isEmpty()) {
                highBound = length - 1;
            } else {
                lowBound = length + 1;
                lengthToPathHash.put(length, firstPathHashes);
            }
        }

        // get the longest common path in lengthToPathHash
        int maxLength = 0;
        for (var length: lengthToPathHash.keySet()) {
            if (length > maxLength) {
                maxLength = length;
            }
        }

        var maxLengthsHashes = lengthToPathHash.get(maxLength);
        var firstPath = paths.iterator().next();


        var result = new HashSet<List<T>>();
        for (var hash: maxLengthsHashes) {
            var subPathNodes = firstPath.subPathsOfLengthWithHash.get(maxLength).get(hash);
            if (subPathNodes != null) {
                result.add(subPathNodes);
            }
        }

        return result;
    }


    /**
     * The soundest strategy is to remove all edges of the conflict node, but it may be too aggressive.
     * By finding the longest common path of the conflict node, we found that some edges are not necessary to remove.
     * So we need to find these edges (marked as tuples like (node_1, node2))
     */
    public void buildExcludeEdges() {
        for (var path: conflictNodesCommonPaths) {
            if (path.size() < 2) {
                continue;
            }

            for (int i = 0; i < path.size(); i++) {
                if (conflictNodes.contains(path.get(i))) {
                    if (i > 0) {
                        excludeEdges.computeIfAbsent(path.get(i), k -> new HashSet<>()).add(path.get(i - 1));
                    }
                    if (i < path.size() - 1) {
                        excludeEdges.computeIfAbsent(path.get(i), k -> new HashSet<>()).add(path.get(i + 1));
                    }
                }
            }
        }

        for (var node: excludeEdges.keySet()) {
            Logging.info("TypeAliasPathManager", String.format("Built Exclude edges: %s: %s", node, excludeEdges.get(node)));
        }
    }


    public void updateNewPath(TypeAliasPath<T> path) {
        allPaths.add(path);
        srcSinkToPathsMap.computeIfAbsent(path.start, k -> new HashMap<>())
                .computeIfAbsent(path.end, k -> new HashSet<>())
                .add(path);
        updateNodeToPathsMap(path);
    }


    public void updateNodeToPathsMap(TypeAliasPath<T> path) {
        for (var node: path.nodes) {
            nodeToPathsMap.computeIfAbsent(node, k -> new HashSet<>()).add(path);
        }
    }


    public Set<TypeAliasPath<T>> getAllPathsFromSource(T source) {
        var result = new HashSet<TypeAliasPath<T>>();
        for (var sk: srcSinkToPathsMap.get(source).keySet()) {
            result.addAll(srcSinkToPathsMap.get(source).get(sk));
        }
        return result;
    }

    public void propagateConstraintByPath(TypeConstraint constraint, TypeAliasPath<T> path) {
        for (var node: path.nodes) {
            nodeToConstraints.computeIfAbsent(node, k -> new HashSet<>()).add(constraint);
        }
    }

    public Set<TypeAliasPath<T>> getAllPathContainsNode(T node) {
        return nodeToPathsMap.get(node);
    }

    public void dump(FileWriter writer) throws Exception {
        if (!hasSrcSink) {
            return;
        }
        writer.write(String.format("Graph: %s\n", graph));
        for (var src: source) {
            writer.write(String.format("\tSource: %s\n", src));
            for (var sk: sink) {
                var paths = srcSinkToPathsMap.get(src).get(sk);
                if (paths == null) {
                    continue;
                }
                writer.write(String.format("\t\tSink: %s\n", sk));
                for (var path: paths) {
                    writer.write(String.format("\t\t\tPath: %s\n", path));
                    if (path.hasConflict) {
                        writer.write("\t\t\t\tConflict\n");
                    } else if (path.noComposite) {
                        writer.write("\t\t\t\tNo Composite\n");
                    } else {
                        writer.write(path.finalConstraint.dumpLayout(4));
                    }
                    writer.write("\t\t\t\t======================================================\n");
                }
            }
        }
        writer.write("\n");
    }
}
