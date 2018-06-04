

# This is a simple example of a cuckoo result parser. The class must implement a 'parse' method which is called
# after cuckoo analysis is completed
# Parse receives two arguments - request and result.
from assemblyline.al.common.result import Result, ResultSection, TAG_TYPE, TEXT_FORMAT, TAG_WEIGHT, SCORE


class ExampleParser(object):

    def parse(self, request, result):
        """

        :param request: The 'request' object containing extracted files, supplementary files, etc
        :param result: The Result() object, which ResultSections should be appended
        :return:
        """

        print "Supplementary Files"
        print request.task.supplementary_files()
        section = ResultSection(SCORE.NULL, "Tutorial service completed")
        section.add_line("Nothing done.")
        result.add_section(section)

