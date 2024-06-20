package blueprint.base.dataflow.SymbolExpr;

import blueprint.utils.Logging;

import java.util.Optional;

public class ParsedExpr {
    public SymbolExpr base = null;
    public SymbolExpr offset = null;
    public SymbolExpr index = null;
    public SymbolExpr scale = null;
    public long offsetValue = 0;


    public static Optional<ParsedExpr> parseFieldAccessExpr(SymbolExpr expr) {
        ParsedExpr parsedExpr = new ParsedExpr();

        if (expr.getNestedExpr().isDereference()) {
            parsedExpr.base = expr.getNestedExpr();
            parsedExpr.offsetValue = 0L;
        }
        else if (expr.getNestedExpr().isRootSymExpr()) {
            parsedExpr.base = expr.getNestedExpr();
            parsedExpr.offsetValue = 0L;
        }
        else {
            parsedExpr.base = expr.getNestedExpr().getBase();
            parsedExpr.offset = expr.getNestedExpr().getOffset();
            parsedExpr.index = expr.getNestedExpr().getIndex();
            parsedExpr.scale = expr.getNestedExpr().getScale();

            if (parsedExpr.offset != null) {
                if (!parsedExpr.offset.isConst()) {
                    Logging.warn("ParsedExpr", String.format("Offset is not a constant: %s, Skipping...", expr));
                    return Optional.empty();
                } else {
                    parsedExpr.offsetValue = parsedExpr.offset.getConstant();
                }
            } else {
                parsedExpr.offsetValue = 0L;
            }
        }

        return Optional.of(parsedExpr);
    }
}
