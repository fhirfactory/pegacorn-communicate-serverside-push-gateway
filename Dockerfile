FROM matrixdotorg/sygnal:v0.9.2

# Copy the pegacorn python source code over the sygnal source code
# This method only works if the changes made to the source code don't introduce new dependencies, 
# that the synapse docker image doesn't already provide.
COPY ./sygnal/http.py /usr/local/lib/python3.7/site-packages/sygnal/
COPY ./sygnal/sygnal.py /usr/local/lib/python3.7/site-packages/sygnal/
COPY ./sygnal/helper/context_factory.py /usr/local/lib/python3.7/site-packages/sygnal/helper/

# Date-time build argument
ARG IMAGE_BUILD_TIMESTAMP
ENV IMAGE_BUILD_TIMESTAMP=${IMAGE_BUILD_TIMESTAMP}
RUN echo IMAGE_BUILD_TIMESTAMP=${IMAGE_BUILD_TIMESTAMP}
