package blueprint.base.dataflow;

import static org.mockito.Mockito.*;
import static org.junit.jupiter.api.Assertions.*;

import blueprint.utils.Logging;
import ghidra.program.model.pcode.HighSymbol;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
public class SymbolExprTest {
    @Mock
    private HighSymbol mockHighSymbol;

    @BeforeEach
    public void setUp() {
        when(mockHighSymbol.getName()).thenReturn("mock");
    }

    @Test
    public void test() {
        var expr1 = new SymbolExpr(mockHighSymbol, 0);
        var expr2 = new SymbolExpr(mockHighSymbol, 8);
        var expr3 = new SymbolExpr(expr1, true);
        var expr4 = new SymbolExpr(expr2, true);
        var expr5 = new SymbolExpr(expr3, true);
        var expr6 = new SymbolExpr(expr4, true);
        var expr7 = new SymbolExpr(expr4, 16);
        var expr8 = new SymbolExpr(expr7, 16);
        var expr9 = new SymbolExpr(expr8, true);
        var expr10 = new SymbolExpr(expr4, 0x10);

        assertEquals(expr1.getRepresentation(), "mock");
        assertEquals(expr2.getRepresentation(), "mock + 0x8");
        assertEquals(expr3.getRepresentation(), "*(mock)");
        assertEquals(expr4.getRepresentation(), "*(mock + 0x8)");
        assertEquals(expr5.getRepresentation(), "*(*(mock))");
        assertEquals(expr6.getRepresentation(), "*(*(mock + 0x8))");
        assertEquals(expr7.getRepresentation(), "*(mock + 0x8) + 0x10");
        assertEquals(expr8.getRepresentation(), "*(mock + 0x8) + 0x20");
        assertEquals(expr9.getRepresentation(), "*(*(mock + 0x8) + 0x20)");
        assertEquals(expr10.getRepresentation(), "*(mock + 0x8) + 0x10");
    }
}