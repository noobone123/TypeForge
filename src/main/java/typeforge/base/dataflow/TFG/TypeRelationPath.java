package typeforge.base.dataflow.TFG;
import typeforge.base.dataflow.expression.NMAE;
import typeforge.base.dataflow.expression.NMAEManager;
import typeforge.base.dataflow.constraint.TypeConstraint;
import typeforge.utils.Logging;
import org.jgrapht.GraphPath;

import java.util.*;

public class TypeRelationPath<T> {
    public final UUID uuid = UUID.randomUUID();
    public final String shortUUID = uuid.toString().substring(0, 8);
    public List<T> nodes;
    public List<TypeFlowGraph.TypeFlowEdge> edges;
    public List<TypeConstraint> forwardMergedConstraints;
    public List<TypeConstraint> backwardMergedConstraints;
    public TypeConstraint finalConstraint = null;
    public boolean evil = false;
    public boolean noComposite = false;
    public T start;
    public T end;
    public Set<TypeFlowGraph.TypeFlowEdge> evilEdges;

    /**
     * Map[SUB_PATH_LENGTH, Map[HASH_CODE, SUB_PATH_NODES]]
     */
    public Map<Integer, Map<Integer, List<T>>> subPathsOfLengthWithHash = new HashMap<>();

    public TypeRelationPath(GraphPath<T, TypeFlowGraph.TypeFlowEdge> path) {
        // update nodes;
        this.nodes = path.getVertexList();
        this.edges = path.getEdgeList();

        this.forwardMergedConstraints = new ArrayList<>();
        this.backwardMergedConstraints = new ArrayList<>();

        this.start = nodes.get(0);
        this.end = nodes.get(nodes.size() - 1);
        this.evilEdges = new HashSet<>();
    }

    public TypeRelationPath(List<T> nodes, List<TypeFlowGraph.TypeFlowEdge> edges) {
        this.nodes = nodes;
        this.edges = edges;

        this.forwardMergedConstraints = new ArrayList<>();
        this.backwardMergedConstraints = new ArrayList<>();

        this.start = nodes.get(0);
        this.end = nodes.get(nodes.size() - 1);
        this.evilEdges = new HashSet<>();
    }

    public boolean tryMergeOnPath(NMAEManager exprManager) {
        for (int i = 0; i < nodes.size(); i++) {
            T node = nodes.get(i);
            TypeConstraint curMergedCon;
            NMAE curExpr = (NMAE) node;
            TypeConstraint curExprCon = exprManager.getConstraint(curExpr);

            if (curExprCon == null) {
                Logging.warn("TypeAliasPath", String.format("Cannot find constraint for %s in path", node));
                curMergedCon = new TypeConstraint();
                Logging.debug("TypeAliasPath", String.format("Created new Constraint %s for %s in path", curMergedCon, curExpr));
            } else {
                curMergedCon = new TypeConstraint(curExprCon);
                Logging.debug("TypeAliasPath", String.format("Created new Constraint %s for %s in path", curMergedCon, curExpr));

                // If Current Expr is fieldAccessExpr, try to merge its memAliasExpr's TypeConstraint
                if (curExpr.isDereference()) {
                    Logging.debug("TypeAliasPath", String.format("Try to merge memAlias into %s", curMergedCon));
                    var mayMemAliases = exprManager.fastGetMayMemAliases(curExpr);
                    for (var alias: mayMemAliases) {
                        if (alias == curExpr) {
                            continue;
                        }
                        var aliasCon = exprManager.getConstraint(alias);
                        if (aliasCon == null) {
                            continue;
                        }
                        var noConflict = curMergedCon.tryMerge(aliasCon);
                        if (!noConflict) {
                            Logging.warn("TypeAliasPath", String.format("Conflict when merging TypeConstraints in memAlias for %s and %s", curExpr, alias));
                        }
                    }
                }
            }

            // Merge forward constraints in the path
            if (i > 0) {
                var prevMergedCon = forwardMergedConstraints.get(i - 1);
                if (prevMergedCon.isEmpty()) {
                    forwardMergedConstraints.add(curMergedCon);
                    continue;
                } else if (curMergedCon.isEmpty()) {
                    forwardMergedConstraints.add(prevMergedCon);
                    continue;
                } else {
                    var noConflict = curMergedCon.tryMerge(prevMergedCon);
                    if (noConflict) {
                        forwardMergedConstraints.add(curMergedCon);
                        continue;
                    }
                    else {
                        Logging.warn("TypeAliasPath", String.format("Conflict when forward merging TypeConstraints on path for %s", curExpr));
                        /* Deprecated Features: Find Evil Edges
                        var rightBoundIndex = i;
                        var leftBoundIndex = tryMergeBackward(exprManager).orElse(-1);
                        // Find evil edges via forwardMergedConstraints and backwardMergedConstraint
                        findEvilEdges(rightBoundIndex, leftBoundIndex);
                        */
                        return false;
                    }
                }
            } else {
                forwardMergedConstraints.add(curMergedCon);
            }
        }

        // update finalConstraint
        finalConstraint = forwardMergedConstraints.get(forwardMergedConstraints.size() - 1);
        return true;
    }


    public Optional<Integer> tryMergeBackward(NMAEManager exprManager) {
        for (int i = nodes.size() - 1; i >= 0; i--) {
            T node = nodes.get(i);
            TypeConstraint curMergedCon;
            NMAE curExpr = (NMAE) node;
            TypeConstraint curExprCon = exprManager.getConstraint(curExpr);

            if (curExprCon == null) {
                curMergedCon = new TypeConstraint();
            } else {
                curMergedCon = new TypeConstraint(curExprCon);
                if (curExpr.isDereference()) {
                    Logging.debug("TypeAliasPath", String.format("Try to merge memAlias into %s", curMergedCon));
                    var mayMemAliases = exprManager.fastGetMayMemAliases(curExpr);
                    for (var alias: mayMemAliases) {
                        if (alias == curExpr) {
                            continue;
                        }
                        var aliasCon = exprManager.getConstraint(alias);
                        if (aliasCon == null) {
                            continue;
                        }
                        var noConflict = curMergedCon.tryMerge(aliasCon);
                        if (!noConflict) {
                            Logging.warn("TypeAliasPath", String.format("Conflict when merging TypeConstraints in memAlias for %s and %s", curExpr, alias));
                        }
                    }
                }
            }

            if (i == nodes.size() - 1) {
                backwardMergedConstraints.add(curMergedCon);
            } else {
                var nextMergedCon = backwardMergedConstraints.get(backwardMergedConstraints.size() - 1);
                if (nextMergedCon.isEmpty()) {
                    backwardMergedConstraints.add(curMergedCon);
                    continue;
                } else if (curMergedCon.isEmpty()) {
                    backwardMergedConstraints.add(nextMergedCon);
                    continue;
                } else {
                    var noConflict = curMergedCon.tryMerge(nextMergedCon);
                    if (noConflict) {
                        backwardMergedConstraints.add(curMergedCon);
                        continue;
                    } else {
                        Logging.warn("TypeAliasPath", String.format("Conflict when backward merging TypeConstraints on path for %s", curExpr));
                        return Optional.of(i);
                    }
                }
            }
        }
        return Optional.empty();
    }

    // TODO: Evil Edges is hard to find accurately, need to be improved
    public void findEvilEdges(int rightBoundIndex, int leftBoundIndex) {
        if (leftBoundIndex == -1) {
            Logging.warn("TypeAliasPath", "Cannot find leftBoundIndex when finding evil edges");
            evilEdges.add(edges.get(rightBoundIndex - 1));
        }
        else if (leftBoundIndex == rightBoundIndex) {
            Logging.debug("TypeAliasPath", "LB == RB");
            evilEdges.add(edges.get(rightBoundIndex));
            evilEdges.add(edges.get(rightBoundIndex - 1));
        }
        else if (leftBoundIndex > rightBoundIndex) {
            Logging.debug("TypeAliasPath", "LB > RB");
            evilEdges.add(edges.get(leftBoundIndex));
            evilEdges.add(edges.get(rightBoundIndex - 1));
            for (int i = rightBoundIndex; i < leftBoundIndex; i++) {
                evilEdges.add(edges.get(i));
            }
        }
        /* leftBoundIndex < rightBoundIndex, this is what we expect */
        else {
            Logging.debug("TypeAliasPath", "LB < RB");
            for (int i = leftBoundIndex; i < rightBoundIndex; i++) {
                evilEdges.add(edges.get(i));
            }
        }

        for (var edge: evilEdges) {
            Logging.debug("TypeAliasPath", String.format("Found Evil Edge: %s", edge));
        }
    }


    public Set<TypeFlowGraph.TypeFlowEdge> getConnectedEdges(T node) {
        var result = new HashSet<TypeFlowGraph.TypeFlowEdge>();
        var nodeIdx = nodes.indexOf(node);
        if (nodeIdx != -1) {
            if (nodeIdx > 0) {
                result.add(edges.get(nodeIdx - 1));
            }
            if (nodeIdx < nodes.size() - 1) {
                result.add(edges.get(nodeIdx));
            }
        }
        return result;
    }

    public void createSubPathsOfLength(int length) {
        if (length < 1) {
            return;
        }
        for (int i = 0; i < nodes.size() - length + 1; i++) {
            var subPathNodes = nodes.subList(i, i + length);
            var hash = getPathsHashCode(subPathNodes);
            if (!subPathsOfLengthWithHash.containsKey(length)) {
                subPathsOfLengthWithHash.put(length, new HashMap<>());
            }
            if (!subPathsOfLengthWithHash.get(length).containsKey(hash)) {
                subPathsOfLengthWithHash.get(length).put(hash, subPathNodes);
            }
        }
    }

    public int getPathsHashCode(List<T> path) {
        int hash = 0;
        for (var t : path) {
            hash = 31 * hash + t.hashCode();
        }
        return hash;
    }

    @Override
    public int hashCode() {
        return edges.hashCode() + nodes.hashCode();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null || getClass() != obj.getClass()) {
            return false;
        }
        TypeRelationPath<?> other = (TypeRelationPath<?>) obj;
        return this.hashCode() == other.hashCode();
    }

    @Override
    public String toString() {
        StringBuilder builder = new StringBuilder();
        builder.append(String.format("Path-%s: ", shortUUID));
        builder.append(nodes.get(0));
        for (int i = 0; i < edges.size(); i++) {
            builder.append(String.format(" --- %s ---> ", edges.get(i).getType()));
            if (i + 1 < nodes.size()) {
                builder.append(nodes.get(i + 1));
            }
        }
        return builder.toString();
    }
}
