<?xml version="1.0" encoding="utf-8"?>
<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" 
                version="1.0">

<!-- Import the DocBook stylesheet -->
<xsl:import href="/usr/share/xml/docbook/stylesheet/nwalsh/manpages/docbook.xsl"/>

<xsl:param name="man.output.encoding" select="'UTF-8'"/>
<xsl:param name="man.charmap.use.subset" select="0"/>
<xsl:param name="chunker.output.method" select="'text'"/>

<xsl:output method="text" encoding="UTF-8" indent="no"/>

<xsl:template match='replaceable'>
  <xsl:text>&lt;</xsl:text><xsl:apply-imports/><xsl:text>&gt;</xsl:text>
</xsl:template>

<xsl:template match="literal">
  <xsl:call-template name="bold">
    <xsl:with-param name="node" select="."/>
    <xsl:with-param name="context" select="."/>
  </xsl:call-template>
</xsl:template>

</xsl:stylesheet>
