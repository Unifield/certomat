FROM scratch
ADD certomat /
EXPOSE 443
CMD [ "/certomat" ]