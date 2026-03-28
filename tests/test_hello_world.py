"""Tests for the sample hello_world tool."""

import pytest
from src.tools import hello_world


@pytest.mark.asyncio
async def test_hello_world_default():
    result = await hello_world()
    assert result == "Hello, World!"


@pytest.mark.asyncio
async def test_hello_world_with_name():
    result = await hello_world(name="Claude")
    assert result == "Hello, Claude!"


@pytest.mark.asyncio
async def test_hello_world_with_empty_string():
    result = await hello_world(name="")
    assert result == "Hello, !"
