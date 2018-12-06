package is.citizen.sdk.resource.token;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

public class TokenWrapper implements Serializable {

    private static final long serialVersionUID = -1543052717770132125L;

    List<Token> tokens = new ArrayList<>();
    private int pageNumber;
    private int pageSize;
    private int numberOfPages;
    private int totalEntriesInAllPages;

    public List<Token> getTokens() {
        return tokens;
    }

    public void setTokens(List<Token> tokens) {
        this.tokens = tokens;
    }

    public int getPageNumber() {
        return pageNumber;
    }

    public void setPageNumber(int pageNumber) {
        this.pageNumber = pageNumber;
    }

    public int getPageSize() {
        return pageSize;
    }

    public void setPageSize(int pageSize) {
        this.pageSize = pageSize;
    }

    public int getNumberOfPages() {
        return numberOfPages;
    }

    public void setNumberOfPages(int numberOfPages) {
        this.numberOfPages = numberOfPages;
    }

    public int getTotalEntriesInAllPages() {
        return totalEntriesInAllPages;
    }

    public void setTotalEntriesInAllPages(int totalEntriesInAllPages) {
        this.totalEntriesInAllPages = totalEntriesInAllPages;
    }
}
