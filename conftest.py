import pytest

@pytest.hookimpl(trylast=True)
def pytest_configure(config):
    # Override terminal reporter's write_sep to remove '===' characters
    reporter = config.pluginmanager.getplugin('terminalreporter')
    if reporter:
        original_write_sep = reporter.write_sep
        
        def custom_write_sep(sep, title=None, **kwargs):
            if sep == '=':
                kwargs.pop('fullwidth', None)
                if title:
                    if title == "test session starts":
                        title = "Test Session"
                    else:
                        title = title.replace("passed", "Passed")
                    reporter.write_line(f" {title} ", **kwargs)
                else:
                    reporter.write_line("", **kwargs)
            else:
                original_write_sep(sep, title, **kwargs)
                
        reporter.write_sep = custom_write_sep
