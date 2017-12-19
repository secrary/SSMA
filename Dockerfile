FROM python:3.5.3

LABEL maintainer="https://github.com/pielco11"
LABEL malice.plugin.repository = "https://github.com/secrary/SSMA.git"
LABEL malice.plugin.category="av"
LABEL malice.plugin.mime="*"
LABEL malice.plugin.docker.engine="*"


RUN git clone https://github.com/pielco11/SSMA.git && cd SSMA && pip3 install -r requirements.txt
RUN chmod +x /SSMA/ssma.py && ln -s /SSMA/ssma.py /bin/ssma

WORKDIR  /malware

CMD ["ssma", "-h"]

ENTRYPOINT ["ssma", "-r", "elasticsearch"]
