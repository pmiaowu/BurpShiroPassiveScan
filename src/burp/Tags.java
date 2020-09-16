package burp;

import java.awt.Component;
import java.util.ArrayList;
import java.util.List;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTabbedPane;
import javax.swing.JTable;
import javax.swing.SwingUtilities;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.TableModel;

public class Tags extends AbstractTableModel implements ITab, IMessageEditorController{
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;

    private String tagName;

    private JSplitPane mjSplitPane;
    private List<Tags.TablesData> Udatas = new ArrayList<Tags.TablesData>();
    private IMessageEditor HRequestTextEditor;
    private IMessageEditor HResponseTextEditor;
    private IHttpRequestResponse currentlyDisplayedItem;
    private Tags.URLTable Utable;
    private JScrollPane UscrollPane;
    private JSplitPane HjSplitPane;
    private JTabbedPane Ltable;
    private JTabbedPane Rtable;

    public Tags(IBurpExtenderCallbacks callbacks, String name) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        this.tagName = name;

        // 创建用户界面
        SwingUtilities.invokeLater(new Runnable()
        {
            @Override
            public void run()
            {
                // 主分隔面板
                mjSplitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);

                // 任务栏面板
                Utable = new Tags.URLTable(Tags.this);
                UscrollPane = new JScrollPane(Utable);

                // 请求与响应界面的分隔面板规则
                HjSplitPane = new JSplitPane();
                HjSplitPane.setDividerLocation(0.5D);

                // 请求的面板
                Ltable = new JTabbedPane();
                HRequestTextEditor = Tags.this.callbacks.createMessageEditor(Tags.this,false);
                Ltable.addTab("Request",HRequestTextEditor.getComponent());

                // 响应的面板
                Rtable = new JTabbedPane();
                HResponseTextEditor = Tags.this.callbacks.createMessageEditor(Tags.this,false);
                Rtable.addTab("Response",HResponseTextEditor.getComponent());

                // 自定义程序UI组件
                HjSplitPane.add(Ltable,"left");
                HjSplitPane.add(Rtable,"right");

                mjSplitPane.add(UscrollPane,"left");
                mjSplitPane.add(HjSplitPane,"right");

                Tags.this.callbacks.customizeUiComponent(mjSplitPane);

                // 将自定义选项卡添加到Burp的UI
                Tags.this.callbacks.addSuiteTab(Tags.this);
            }
        });
    }

    @Override
    public String getTabCaption()
    {
        return this.tagName;
    }

    @Override
    public Component getUiComponent()
    {
        return mjSplitPane;
    }

    @Override
    public int getRowCount()
    {
        return this.Udatas.size();
    }

    @Override
    public int getColumnCount()
    {
        return 6;
    }

    @Override
    public String getColumnName(int columnIndex) {
        switch (columnIndex) {
            case 0:
                return "#";
            case 1:
                return "extensionMethod";
            case 2:
                return "requestMethod";
            case 3:
                return "url";
            case 4:
                return "statusCode";
            case 5:
                return "issue";
        }
        return null;
    }

    @Override
    public Class<?> getColumnClass(int columnIndex)
    {
        return String.class;
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex)
    {
        Tags.TablesData datas = this.Udatas.get(rowIndex);
        switch (columnIndex) {
            case 0:
                return datas.id;
            case 1:
                return datas.extensionMethod;
            case 2:
                return datas.requestMethod;
            case 3:
                return datas.url;
            case 4:
                return datas.statusCode;
            case 5:
                return datas.issue;
        }
        return null;
    }

    @Override
    public byte[] getRequest()
    {
        return currentlyDisplayedItem.getRequest();
    }

    @Override
    public byte[] getResponse()
    {
        return currentlyDisplayedItem.getResponse();
    }

    @Override
    public IHttpService getHttpService()
    {
        return currentlyDisplayedItem.getHttpService();
    }

    /**
     * 新增任务至任务栏面板
     * @param extensionMethod
     * @param requestMethod
     * @param url
     * @param statusCode
     * @param issue
     * @param requestResponse
     * @return int id
     */
    public int add(String extensionMethod, String requestMethod, String url,
                   String statusCode, String issue, IHttpRequestResponse requestResponse) {
        synchronized (this.Udatas) {
            // 新增任务至任务栏面板
            int id = this.Udatas.size();
            this.Udatas.add(
                new TablesData(
                        id,
                        extensionMethod,
                        requestMethod,
                        url,
                        statusCode,
                        issue,
                        requestResponse
                )
            );
            fireTableRowsInserted(id,id);
            return id;
        }
    }

    /**
     * 更新任务状态至任务栏面板
     * @param id
     * @param extensionMethod
     * @param requestMethod
     * @param url
     * @param statusCode
     * @param issue
     * @param requestResponse
     * @return int id
     */
    public int save(int id, String extensionMethod, String requestMethod,
                    String url, String statusCode, String issue,
                    IHttpRequestResponse requestResponse) {
        synchronized (this.Udatas) {
            this.Udatas.set(
                id,
                new TablesData(
                        id,
                        extensionMethod,
                        requestMethod,
                        url,
                        statusCode,
                        issue,
                        requestResponse
                )
            );
            fireTableRowsUpdated(id,id);
            return id;
        }
    }

    /**
     * 自定义Table
     */
    public class URLTable extends JTable{
        public URLTable(TableModel tableModel) {
            super(tableModel);
        }

        public void changeSelection(int row, int col, boolean toggle, boolean extend) {
            Tags.TablesData dataEntry = Tags.this.Udatas.get(convertRowIndexToModel(row));
            HRequestTextEditor.setMessage(dataEntry.requestResponse.getRequest(), true);
            HResponseTextEditor.setMessage(dataEntry.requestResponse.getResponse(),false);
            currentlyDisplayedItem = dataEntry.requestResponse;
            super.changeSelection(row, col, toggle, extend);
        }
    }

    /**
     * 界面显示数据存储模块
     */
    public static class TablesData {
        final int id;
        final String extensionMethod;
        final String requestMethod;
        final String url;
        final String statusCode;
        final String issue;
        final IHttpRequestResponse requestResponse;

        public TablesData(int id, String extensionMethod, String requestMethod,
                          String url, String statusCode, String issue,
                          IHttpRequestResponse requestResponse) {
            this.id = id;
            this.extensionMethod = extensionMethod;
            this.requestMethod = requestMethod;
            this.url = url;
            this.statusCode = statusCode;
            this.issue = issue;
            this.requestResponse = requestResponse;
        }
    }
}
