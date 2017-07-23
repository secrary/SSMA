FROM python:3.5.3

LABEL maintainer "https://github.com/pielco11"
LABEL malice.plugin.repository = "https://github.com/secrary/SSMA.git"
LABEL malice.plugin.category="av"
LABEL malice.plugin.mime="*"
LABEL malice.plugin.docker.engine="*"

WORKDIR  /mal

ADD . /mal

RUN pip install -r requirements.txt

CMD ["python3", "ssma.py", "-h "]

ENTRYPOINT ["python3", "ssma.py", "-r", "output" ,"-f"]
